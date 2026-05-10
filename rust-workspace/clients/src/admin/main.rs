//! idv2-admin — authority-only CLI.
//!
//! Subcommands:
//!   create-election   create + fund the ElectionAccount PDA
//!   init-registry     create the VoterRegistryAccount for an election
//!   set-candidates    write the candidate roster (advances Draft→RegOpen)
//!   advance-phase     slot-gated phase transition (authority signed)
//!   register-voter    relay path: insert one commitment into the Merkle tree
//!
//! Program IDs are supplied via --election-program / --voter-program (required
//! after devnet deployment).  Slot values for election windows are passed as
//! absolute slot numbers; use `solana slot` to find the current slot.
//!
//! Quick devnet demo:
//!   SLOT=$(solana slot --url devnet)
//!   cargo run -p clients --bin idv2-admin -- \
//!     --keypair .keys/authority.json \
//!     --election-program <ID> --voter-program <ID> \
//!     create-election --id 1 \
//!       --reg-open  $((SLOT+100))  --reg-close $((SLOT+500)) \
//!       --vote-open $((SLOT+600))  --vote-close $((SLOT+1000)) \
//!       --agg-pubkey <base58>

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
};
use std::str::FromStr;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "idv2-admin", version, about = "Authority-only CLI for idv2")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    /// Path to authority keypair JSON (Solana format — 64-byte array).
    #[arg(long, default_value = ".keys/authority.json", global = true)]
    keypair: String,

    /// Solana RPC endpoint.
    #[arg(long, default_value = "https://api.devnet.solana.com", global = true)]
    rpc: String,

    /// election_registry program ID (base58).  Required for most commands.
    #[arg(long, global = true)]
    election_program: Option<String>,

    /// voter_registry program ID (base58).  Required for registry commands.
    #[arg(long, global = true)]
    voter_program: Option<String>,

    /// tally program ID (base58).  Required for init-tally / finalise-tally.
    #[arg(long, global = true)]
    tally_program: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create and fund the ElectionAccount PDA on-chain.
    CreateElection {
        #[arg(long)] id: u64,
        #[arg(long, help = "slot number (use `solana slot` to get current)")] reg_open: u64,
        #[arg(long)] reg_close: u64,
        #[arg(long)] vote_open: u64,
        #[arg(long)] vote_close: u64,
        /// Ed25519 pubkey (base58) — ballot-signing key from key_ceremony.
        #[arg(long)] agg_pubkey: String,
    },

    /// One-time: create the VoterRegistryAccount for an election.
    /// Call this after create-election and before registration opens.
    InitRegistry {
        #[arg(long)] election_id: u64,
    },

    /// Write the candidate roster.  Advances phase Draft → RegOpen on first call.
    /// Candidates: comma-separated "id:name:party" triples.
    /// Example: --candidates "0:Atiku Abubakar:PDP,1:Bola Tinubu:APC"
    SetCandidates {
        #[arg(long)] election_id: u64,
        #[arg(long)] candidates: String,
    },

    /// Slot-gated authority phase transition.
    /// Phases: 1=RegOpen→2=RegClosed, 2→3=VotingOpen, 3→4=VotingClosed, 4→5=Tallied
    AdvancePhase {
        #[arg(long)] election_id: u64,
        #[arg(long)] target: u8,
    },

    /// Relay path: insert one voter commitment into the Merkle tree.
    /// Calls the SMT server for the insertion path, then sends the tx.
    RegisterVoter {
        #[arg(long)] election_id: u64,
        /// Pedersen commitment (64 hex chars = 32 bytes).
        #[arg(long)] commitment: String,
        /// SMT server URL.
        #[arg(long, default_value = "http://localhost:8765")] smt_url: String,
    },

    /// One-time: create the TallyAccount PDA for an election.
    /// Must be called before advancing to VotingOpen.
    InitTally {
        #[arg(long)] election_id: u64,
    },

    /// Authority: lock the TallyAccount after voting closes.
    /// Sets finalized=1; tally program rejects further accumulate_votes calls.
    FinaliseTally {
        #[arg(long)] election_id: u64,
    },

    /// Dev-only: generate a test voter's commitment, nullifier, and HSM sig
    /// using a local Ed25519 keypair file (bypasses PKCS#11/SoftHSM).
    /// Outputs shell-eval-able vars: COMMITMENT NULLIFIER HSM_SIG AUTHORITY_PK
    GenTestVoter {
        #[arg(long)] election_id: u64,
        /// Deterministic voter index — different index → different commitment/nullifier.
        #[arg(long)] voter_index: u64,
        /// Ed25519 keypair that acts as the ballot-signing authority (= .keys/aggregation.json).
        #[arg(long, default_value = ".keys/aggregation.json")] signing_keypair: String,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new_with_commitment(
        cli.rpc.clone(),
        CommitmentConfig::confirmed(),
    );
    let payer = load_keypair(&cli.keypair)?;

    match cli.command {
        Cmd::CreateElection { id, reg_open, reg_close, vote_open, vote_close, agg_pubkey } => {
            let prog = require_program(&cli.election_program, "election-program")?;
            create_election(&client, &payer, prog, id, reg_open, reg_close, vote_open, vote_close, &agg_pubkey)?;
        }
        Cmd::InitRegistry { election_id } => {
            let eprog = require_program(&cli.election_program, "election-program")?;
            let vprog = require_program(&cli.voter_program, "voter-program")?;
            init_registry(&client, &payer, eprog, vprog, election_id)?;
        }
        Cmd::SetCandidates { election_id, candidates } => {
            let prog = require_program(&cli.election_program, "election-program")?;
            set_candidates(&client, &payer, prog, election_id, &candidates)?;
        }
        Cmd::AdvancePhase { election_id, target } => {
            let prog = require_program(&cli.election_program, "election-program")?;
            advance_phase(&client, &payer, prog, election_id, target)?;
        }
        Cmd::RegisterVoter { election_id, commitment, smt_url } => {
            let eprog = require_program(&cli.election_program, "election-program")?;
            let vprog = require_program(&cli.voter_program, "voter-program")?;
            register_voter(&client, &payer, eprog, vprog, election_id, &commitment, &smt_url)?;
        }
        Cmd::InitTally { election_id } => {
            let tprog = require_program(&cli.tally_program, "tally-program")?;
            init_tally(&client, &payer, tprog, election_id)?;
        }
        Cmd::FinaliseTally { election_id } => {
            let eprog = require_program(&cli.election_program, "election-program")?;
            let tprog = require_program(&cli.tally_program,    "tally-program")?;
            finalise_tally(&client, &payer, eprog, tprog, election_id)?;
        }
        Cmd::GenTestVoter { election_id, voter_index, ref signing_keypair } => {
            gen_test_voter(election_id, voter_index, signing_keypair)?;
        }
    }
    Ok(())
}

// ── create-election ───────────────────────────────────────────────────────────

fn create_election(
    client: &RpcClient,
    payer: &Keypair,
    prog: Pubkey,
    id: u64,
    reg_open: u64, reg_close: u64, vote_open: u64, vote_close: u64,
    agg_pubkey_b58: &str,
) -> anyhow::Result<()> {
    let eid_le = id.to_le_bytes();
    let (election_pda, bump) = Pubkey::find_program_address(&[b"election", &eid_le], &prog);

    let agg_pk = parse_pubkey(agg_pubkey_b58)?;
    let lamports = client.get_minimum_balance_for_rent_exemption(
        election_registry::ELECTION_ACCOUNT_SIZE,
    )?;

    // Data layout: tag(1) + eid(8) + reg_open(8) + reg_close(8) + vote_open(8) + vote_close(8)
    //              + agg_pk(32) + lamports(8) + bump(1) = 82 bytes
    let mut data = vec![0u8]; // ix tag = 0
    data.extend_from_slice(&id.to_le_bytes());
    data.extend_from_slice(&reg_open.to_le_bytes());
    data.extend_from_slice(&reg_close.to_le_bytes());
    data.extend_from_slice(&vote_open.to_le_bytes());
    data.extend_from_slice(&vote_close.to_le_bytes());
    data.extend_from_slice(&agg_pk.to_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.push(bump);

    let ix = Instruction {
        program_id: prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(election_pda, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;
    println!("create-election  id={id}  sig={sig}");
    println!("ElectionAccount  {election_pda}");
    Ok(())
}

// ── init-registry ─────────────────────────────────────────────────────────────

fn init_registry(
    client: &RpcClient,
    payer: &Keypair,
    _election_prog: Pubkey,
    voter_prog: Pubkey,
    election_id: u64,
) -> anyhow::Result<()> {
    let eid_le = election_id.to_le_bytes();
    let (vr_pda, bump) = Pubkey::find_program_address(
        &[b"voter_registry", &eid_le],
        &voter_prog,
    );
    let lamports = client.get_minimum_balance_for_rent_exemption(
        voter_registry::VoterRegistryAccount::LEN,
    )?;

    // ix tag = 1, election_id(8), lamports(8), bump(1) = 18 bytes
    let mut data = vec![1u8];
    data.extend_from_slice(&election_id.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.push(bump);

    let ix = Instruction {
        program_id: voter_prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(vr_pda, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;
    println!("init-registry  election_id={election_id}  sig={sig}");
    println!("VoterRegistry  {vr_pda}");
    Ok(())
}

// ── set-candidates ────────────────────────────────────────────────────────────

fn set_candidates(
    client: &RpcClient,
    payer: &Keypair,
    prog: Pubkey,
    election_id: u64,
    candidates_str: &str,
) -> anyhow::Result<()> {
    let eid_le = election_id.to_le_bytes();
    let (election_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &prog);

    // Parse "id:name:party,id:name:party,..."
    let entries: Vec<(u8, [u8; 32], [u8; 15])> = candidates_str
        .split(',')
        .map(|entry| {
            let parts: Vec<&str> = entry.trim().splitn(3, ':').collect();
            if parts.len() != 3 {
                anyhow::bail!("candidate must be 'id:name:party', got: {entry}");
            }
            let id: u8 = parts[0].trim().parse()?;
            let mut name = [0u8; 32];
            let nb = parts[1].trim().as_bytes();
            name[..nb.len().min(32)].copy_from_slice(&nb[..nb.len().min(32)]);
            let mut party = [0u8; 15];
            let pb = parts[2].trim().as_bytes();
            party[..pb.len().min(15)].copy_from_slice(&pb[..pb.len().min(15)]);
            Ok((id, name, party))
        })
        .collect::<anyhow::Result<_>>()?;

    if entries.is_empty() || entries.len() > 32 {
        anyhow::bail!("candidate count must be 1..=32");
    }

    // ix tag = 1, election_id(8), count(1), candidates(count*48)
    let mut data = vec![1u8];
    data.extend_from_slice(&election_id.to_le_bytes());
    data.push(entries.len() as u8);
    for (id, name, party) in &entries {
        data.push(*id);
        data.extend_from_slice(name);
        data.extend_from_slice(party);
    }

    let ix = Instruction {
        program_id: prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(election_pda, false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;
    println!("set-candidates  election_id={election_id}  count={}  sig={sig}", entries.len());
    Ok(())
}

// ── advance-phase ─────────────────────────────────────────────────────────────

fn advance_phase(
    client: &RpcClient,
    payer: &Keypair,
    prog: Pubkey,
    election_id: u64,
    target: u8,
) -> anyhow::Result<()> {
    let eid_le = election_id.to_le_bytes();
    let (election_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &prog);

    // ix tag = 3, election_id(8), target(1)
    let mut data = vec![3u8];
    data.extend_from_slice(&election_id.to_le_bytes());
    data.push(target);

    let ix = Instruction {
        program_id: prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(election_pda, false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;
    println!("advance-phase  election_id={election_id}  target={target}  sig={sig}");
    Ok(())
}

// ── register-voter ────────────────────────────────────────────────────────────

fn register_voter(
    client: &RpcClient,
    payer: &Keypair,
    election_prog: Pubkey,
    voter_prog: Pubkey,
    election_id: u64,
    commitment_hex: &str,
    smt_url: &str,
) -> anyhow::Result<()> {
    let commitment = from_hex_32(commitment_hex)
        .context("--commitment must be 64 hex chars (32 bytes)")?;

    let eid_le = election_id.to_le_bytes();
    let (election_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &election_prog);
    let (vr_pda, _) = Pubkey::find_program_address(&[b"voter_registry", &eid_le], &voter_prog);

    // Read current leaf_count to determine this voter's leaf index
    let vr_account = client.get_account(&vr_pda)
        .context("VoterRegistryAccount not found — run init-registry first")?;
    // leaf_count is at offset 48 in VoterRegistryAccount layout
    let leaf_index: u64 = u64::from_le_bytes(
        vr_account.data[48..56].try_into()
            .context("VoterRegistryAccount data too short")?
    );

    let idx_le = leaf_index.to_le_bytes();
    let (leaf_pda, leaf_bump) = Pubkey::find_program_address(
        &[b"leaf", &eid_le, &idx_le],
        &voter_prog,
    );
    let leaf_lamports = client.get_minimum_balance_for_rent_exemption(
        voter_registry::LeafAccount::LEN,
    )?;

    // data: tag(1) + election_id(8) + commitment(32) + leaf_lamports(8) + leaf_bump(1) = 50 bytes
    let mut data = vec![0u8]; // tag = 0 (insert_commitment)
    data.extend_from_slice(&election_id.to_le_bytes());
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&leaf_lamports.to_le_bytes());
    data.push(leaf_bump);

    let ix = Instruction {
        program_id: voter_prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(election_pda, false),
            AccountMeta::new(vr_pda, false),
            AccountMeta::new(leaf_pda, false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;

    // Notify SMT server so it can append the commitment to its off-chain tree
    let insert_url = format!("{smt_url}/insert");
    let _ = ureq::post(&insert_url)
        .send_json(serde_json::json!({ "commitment": commitment_hex }));

    println!("register-voter  election_id={election_id}  leaf={leaf_index}  sig={sig}");
    println!("LeafAccount     {leaf_pda}");
    println!("commitment      {commitment_hex}");
    Ok(())
}

// ── init-tally ────────────────────────────────────────────────────────────────

fn init_tally(
    client: &RpcClient,
    payer: &Keypair,
    tally_prog: Pubkey,
    election_id: u64,
) -> anyhow::Result<()> {
    let eid_le = election_id.to_le_bytes();
    let (tally_pda, bump) = Pubkey::find_program_address(&[b"tally", &eid_le], &tally_prog);
    let lamports = client.get_minimum_balance_for_rent_exemption(tally::TallyAccount::LEN)?;

    // data: tag(1) + election_id(8) + lamports(8) + bump(1) = 18 bytes
    let mut data = vec![3u8]; // ix_tag = 3 (init_tally)
    data.extend_from_slice(&eid_le);
    data.extend_from_slice(&lamports.to_le_bytes());
    data.push(bump);

    let ix = Instruction {
        program_id: tally_prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(tally_pda, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;
    println!("init-tally  election_id={election_id}  sig={sig}");
    println!("TallyAccount  {tally_pda}");
    Ok(())
}

// ── finalise-tally ────────────────────────────────────────────────────────────

fn finalise_tally(
    client: &RpcClient,
    payer: &Keypair,
    election_prog: Pubkey,
    tally_prog: Pubkey,
    election_id: u64,
) -> anyhow::Result<()> {
    let eid_le = election_id.to_le_bytes();
    let (election_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &election_prog);
    let (tally_pda, _)    = Pubkey::find_program_address(&[b"tally",    &eid_le], &tally_prog);

    // data: tag(1) + election_id(8) = 9 bytes
    let mut data = vec![1u8]; // ix_tag = 1 (finalise_tally)
    data.extend_from_slice(&eid_le);

    let ix = Instruction {
        program_id: tally_prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(election_pda, false),
            AccountMeta::new(tally_pda, false),
        ],
        data,
    };

    let sig = send_and_confirm(client, payer, &[ix])?;
    println!("finalise-tally  election_id={election_id}  sig={sig}");
    Ok(())
}

// ── gen-test-voter ────────────────────────────────────────────────────────────
//
// Dev-only: derive deterministic test commitment + nullifier and sign with a
// local Ed25519 keypair (bypasses PKCS#11/SoftHSM for devnet automation).
//
// commitment = SHA-256("idv2:test:commitment:" || voter_index_le8)
// nullifier  = SHA-256("idv2:test:nullifier:"  || voter_index_le8 || election_id_le8)
// message    = b"IDV2-v1-ballot" || nullifier || commitment  (78 bytes)
// hsm_sig    = Ed25519_sign(signing_key, message)
// authority_pk = pubkey bytes of signing_key

fn gen_test_voter(
    election_id: u64,
    voter_index: u64,
    signing_keypair_path: &str,
) -> anyhow::Result<()> {
    let signer = load_keypair(signing_keypair_path)?;

    let idx_le = voter_index.to_le_bytes();
    let eid_le = election_id.to_le_bytes();

    let commitment: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"idv2:test:commitment:");
        h.update(idx_le);
        h.finalize().into()
    };

    let nullifier: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"idv2:test:nullifier:");
        h.update(idx_le);
        h.update(eid_le);
        h.finalize().into()
    };

    // Ballot message: domain || nullifier || commitment  (14 + 32 + 32 = 78 bytes)
    let mut msg = [0u8; 78];
    msg[..14].copy_from_slice(b"IDV2-v1-ballot");
    msg[14..46].copy_from_slice(&nullifier);
    msg[46..78].copy_from_slice(&commitment);

    let sig = signer.sign_message(&msg);
    let authority_pk = signer.pubkey();

    // Output shell-eval-able vars — one per line so the script can `read` them
    println!("COMMITMENT={}", to_hex(&commitment));
    println!("NULLIFIER={}", to_hex(&nullifier));
    println!("HSM_SIG={}", to_hex(sig.as_ref()));
    println!("AUTHORITY_PK={}", to_hex(&authority_pk.to_bytes()));
    println!("LEAF_INDEX={voter_index}");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_keypair(path: &str) -> anyhow::Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("keypair file not found: {path}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .context("keypair file must be a JSON array of 64 integers")?;
    if bytes.len() < 32 {
        anyhow::bail!("keypair must have at least 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    Ok(Keypair::new_from_array(arr))
}

fn require_program(opt: &Option<String>, flag: &str) -> anyhow::Result<Pubkey> {
    let s = opt.as_deref()
        .ok_or_else(|| anyhow!("--{flag} is required for this subcommand"))?;
    parse_pubkey(s)
}

fn parse_pubkey(s: &str) -> anyhow::Result<Pubkey> {
    Pubkey::from_str(s).with_context(|| format!("invalid pubkey: {s}"))
}

fn send_and_confirm(
    client: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
) -> anyhow::Result<String> {
    let recent_bh = client.get_latest_blockhash()?;
    let msg = Message::new(instructions, Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, recent_bh);
    let sig = client
        .send_and_confirm_transaction(&tx)
        .context("transaction failed")?;
    Ok(sig.to_string())
}

fn from_hex_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
