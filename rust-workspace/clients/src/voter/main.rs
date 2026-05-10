//! idv2-voter — booth-side cast-vote CLI.
//!
//! Builds and broadcasts a ballot::cast transaction.  In the demo the nullifier
//! and commitment are supplied directly (output of the enclave key_ceremony /
//! issuance flow).  In the booth application these are derived inside the enclave
//! and passed programmatically to the same transaction-building logic here.
//!
//! Usage:
//!   cargo run -p clients --bin idv2-voter -- \
//!     --keypair .keys/relayer.json \
//!     --ballot-program  <ID>  \
//!     --election-program <ID> \
//!     --voter-program    <ID> \
//!     cast-vote \
//!       --election-id  1 \
//!       --candidate-id 0 \
//!       --state-id     25 \
//!       --lga-id       301 \
//!       --nullifier    <64-hex> \
//!       --hsm-sig      <128-hex> \
//!       --authority-pk <64-hex> \
//!       --leaf-index   0
//!
//! The relayer keypair (--keypair) pays tx fees.  It does NOT need to be the
//! election authority.  Any funded keypair works.

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
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

// Fixed Solana runtime addresses — same on every cluster.
const ED25519_PROG: &str = "Ed25519SigVerify111111111111111111111111111";
const IXS_SYSVAR:  &str = "Sysvar1nstructions1111111111111111111111111";

// Signing domain separator — must match the on-chain ballot program exactly.
const BALLOT_PREFIX: &[u8] = b"IDV2-v1-ballot"; // 14 bytes

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "idv2-voter", version, about = "Booth-side voter CLI for idv2")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    /// Relayer keypair (pays tx fees; does not need authority).
    #[arg(long, default_value = ".keys/relayer.json", global = true)]
    keypair: String,

    #[arg(long, default_value = "https://api.devnet.solana.com", global = true)]
    rpc: String,

    #[arg(long, global = true)] ballot_program:   Option<String>,
    #[arg(long, global = true)] election_program:  Option<String>,
    #[arg(long, global = true)] voter_program:     Option<String>,
    #[arg(long, global = true)] tally_program:     Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build and broadcast a ballot::cast transaction.
    CastVote {
        #[arg(long)] election_id:   u64,
        #[arg(long)] candidate_id:  u8,
        /// State ID written to BallotAccount (1-based, matches INEC state codes).
        #[arg(long)] state_id:      u8,
        /// LGA ID (16-bit, matches INEC LGA codes).
        #[arg(long)] lga_id:        u16,
        /// SHA-3-256 nullifier = H(credential_secret ‖ election_id_le).
        #[arg(long)] nullifier:     String,
        /// Ed25519 signature from HSM over IDV2-v1-ballot ‖ nullifier ‖ commitment (128 hex chars).
        #[arg(long)] hsm_sig:       String,
        /// Ed25519 pubkey matching ElectionAccount.aggregation_pubkey (64 hex chars).
        #[arg(long)] authority_pk:  String,
        /// Leaf index returned by register-voter (0-based position in the Merkle tree).
        #[arg(long)] leaf_index:    u64,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new_with_commitment(cli.rpc.clone(), CommitmentConfig::confirmed());
    let payer  = load_keypair(&cli.keypair)?;

    match cli.command {
        Cmd::CastVote { election_id, candidate_id, state_id, lga_id,
                         ref nullifier, ref hsm_sig, ref authority_pk,
                         leaf_index } => {
            cast_vote(
                &client, &payer, &cli,
                election_id, candidate_id, state_id, lga_id,
                nullifier, hsm_sig, authority_pk,
                leaf_index,
            )?;
        }
    }
    Ok(())
}

// ── cast-vote ─────────────────────────────────────────────────────────────────

fn cast_vote(
    client: &RpcClient,
    payer: &Keypair,
    cli: &Cli,
    election_id: u64,
    candidate_id: u8,
    state_id: u8,
    lga_id: u16,
    nullifier_hex: &str,
    hsm_sig_hex: &str,
    authority_pk_hex: &str,
    leaf_index: u64,
) -> anyhow::Result<()> {
    let ballot_prog   = require_program(&cli.ballot_program,   "ballot-program")?;
    let election_prog = require_program(&cli.election_program, "election-program")?;
    let voter_prog    = require_program(&cli.voter_program,    "voter-program")?;
    let tally_prog    = require_program(&cli.tally_program,    "tally-program")?;

    let nullifier    = from_hex_32(nullifier_hex).context("--nullifier")?;
    let hsm_sig      = from_hex_64(hsm_sig_hex).context("--hsm-sig")?;
    let authority_pk = from_hex_32(authority_pk_hex).context("--authority-pk")?;

    // ── Derive PDAs ───────────────────────────────────────────────────────────
    let eid_le = election_id.to_le_bytes();

    let (election_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &election_prog);
    let (vr_pda, _)       = Pubkey::find_program_address(&[b"voter_registry", &eid_le], &voter_prog);
    let (leaf_pda, _)     = Pubkey::find_program_address(
        &[b"leaf", &eid_le, &leaf_index.to_le_bytes()],
        &voter_prog,
    );
    let (ballot_pda, ballot_bump) = Pubkey::find_program_address(
        &[b"ballot", &eid_le, &nullifier],
        &ballot_prog,
    );
    let (null_pda, null_bump) = Pubkey::find_program_address(
        &[b"nullifier", &eid_le, &nullifier],
        &ballot_prog,
    );
    let (tally_pda, _) = Pubkey::find_program_address(&[b"tally", &eid_le], &tally_prog);

    // ── Fetch commitment from LeafAccount (authoritative on-chain source) ─────
    // The LeafAccount was written during registration.  We read its commitment
    // field here solely to reconstruct the ballot message for the Ed25519
    // precompile — it is never re-sent as instruction data to the ballot program.
    let leaf_account_data = client
        .get_account(&leaf_pda)
        .with_context(|| format!("LeafAccount not found for leaf_index={leaf_index}"))?;
    if leaf_account_data.data.len() < 56 {
        anyhow::bail!("LeafAccount too short ({} bytes)", leaf_account_data.data.len());
    }
    let commitment: [u8; 32] = leaf_account_data.data[24..56]
        .try_into()
        .context("commitment slice")?;

    // ── Build 78-byte ballot message: prefix ‖ nullifier ‖ commitment ─────────
    let mut ballot_msg = [0u8; 78];
    ballot_msg[..14].copy_from_slice(BALLOT_PREFIX);
    ballot_msg[14..46].copy_from_slice(&nullifier);
    ballot_msg[46..78].copy_from_slice(&commitment);

    // ── Ed25519 precompile instruction (must be ix[0]) ────────────────────────
    let ed25519_ix = build_ed25519_ix(&authority_pk, &hsm_sig, &ballot_msg);

    let ballot_lamports = client.get_minimum_balance_for_rent_exemption(ballot::BallotAccount::LEN)?;
    let null_lamports   = client.get_minimum_balance_for_rent_exemption(ballot::NullifierAccount::LEN)?;

    // ── Build cast instruction data (166 bytes after tag = 167 total) ─────────
    // Layout: tag(1) + election_id(8) + leaf_index(8) + nullifier(32) +
    //         candidate_id(1) + state_id(1) + lga_id(2) +
    //         ballot_lamports(8) + null_lamports(8) +
    //         ballot_bump(1) + null_bump(1) + hsm_sig(64) + authority_pk(32)
    // commitment is read zero-copy from LeafAccount on-chain; not sent here.
    let mut data = vec![0u8]; // ix tag = 0 (cast)
    data.extend_from_slice(&election_id.to_le_bytes());
    data.extend_from_slice(&leaf_index.to_le_bytes());
    data.extend_from_slice(&nullifier);
    data.push(candidate_id);
    data.push(state_id);
    data.extend_from_slice(&lga_id.to_le_bytes());
    data.extend_from_slice(&ballot_lamports.to_le_bytes());
    data.extend_from_slice(&null_lamports.to_le_bytes());
    data.push(ballot_bump);
    data.push(null_bump);
    data.extend_from_slice(&hsm_sig);
    data.extend_from_slice(&authority_pk);

    let ixs_sysvar_pk = Pubkey::from_str(IXS_SYSVAR).unwrap();
    let ed25519_prog_pk = Pubkey::from_str(ED25519_PROG).unwrap();

    let cast_ix = Instruction {
        program_id: ballot_prog,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),                              // [0]  relayer
            AccountMeta::new_readonly(election_pda, false),                      // [1]  election_account
            AccountMeta::new_readonly(vr_pda, false),                            // [2]  voter_registry
            AccountMeta::new_readonly(leaf_pda, false),                          // [3]  leaf_account
            AccountMeta::new(ballot_pda, false),                                 // [4]  ballot_account
            AccountMeta::new(null_pda, false),                                   // [5]  nullifier_account
            AccountMeta::new_readonly(sysvar::clock::id(), false),               // [6]  clock
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),// [7]  system
            AccountMeta::new(tally_pda, false),                                  // [8]  tally_account
            AccountMeta::new_readonly(tally_prog, false),                        // [9]  tally_program
            AccountMeta::new_readonly(ixs_sysvar_pk, false),                     // [10] ixs_sysvar
        ],
        data,
    };
    let _ = ed25519_prog_pk; // program_id is embedded in ed25519_ix already

    let sig = send_and_confirm(client, payer, &[ed25519_ix, cast_ix])?;
    println!("cast-vote  election_id={election_id}  candidate={candidate_id}  sig={sig}");
    println!("BallotAccount    {ballot_pda}");
    println!("NullifierAccount {null_pda}");
    println!("Thank you.");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_keypair(path: &str) -> anyhow::Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("keypair not found: {path}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .context("keypair must be a JSON array of 64 integers")?;
    if bytes.len() < 32 {
        anyhow::bail!("keypair must have at least 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    Ok(Keypair::new_from_array(arr))
}

fn require_program(opt: &Option<String>, flag: &str) -> anyhow::Result<Pubkey> {
    let s = opt.as_deref()
        .ok_or_else(|| anyhow!("--{flag} is required for cast-vote"))?;
    Pubkey::from_str(s).with_context(|| format!("invalid pubkey for --{flag}"))
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

fn from_hex_64(s: &str) -> anyhow::Result<[u8; 64]> {
    let s = s.trim_start_matches("0x");
    if s.len() != 128 {
        anyhow::bail!("expected 128 hex chars (64 bytes), got {}", s.len());
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

// ── Ed25519 precompile instruction builder ────────────────────────────────────
//
// Builds the native Ed25519 precompile instruction that must be ix[0] in the
// transaction so the ballot program can confirm it ran via the Instructions sysvar.
//
// Precompile data layout (1 signature entry, 190 bytes for a 78-byte message):
//   [0]       count           : u8   = 1
//   [1]       padding         : u8   = 0
//   [2..4]    sig_offset      : u16  = 16        (sig starts at byte 16)
//   [4..6]    sig_ix_index    : u16  = 0xFFFF    (data is in this ix)
//   [6..8]    pk_offset       : u16  = 80        (pk starts after 64-byte sig)
//   [8..10]   pk_ix_index     : u16  = 0xFFFF
//   [10..12]  msg_offset      : u16  = 112       (msg starts after sig+pk)
//   [12..14]  msg_len         : u16  = 78
//   [14..16]  msg_ix_index    : u16  = 0xFFFF
//   [16..80]  sig             : [u8; 64]
//   [80..112] pubkey          : [u8; 32]
//   [112..190] message        : [u8; 78]
fn build_ed25519_ix(pubkey: &[u8; 32], sig: &[u8; 64], message: &[u8; 78]) -> Instruction {
    let ed25519_prog = Pubkey::from_str(ED25519_PROG).unwrap();

    let mut data = vec![0u8; 190];
    data[0] = 1;        // count = 1 signature entry
    data[1] = 0;        // padding

    // sig_offset=16, sig_ix_index=0xFFFF
    data[2..4].copy_from_slice(&16u16.to_le_bytes());
    data[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    // pk_offset=80, pk_ix_index=0xFFFF
    data[6..8].copy_from_slice(&80u16.to_le_bytes());
    data[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
    // msg_offset=112, msg_len=78, msg_ix_index=0xFFFF
    data[10..12].copy_from_slice(&112u16.to_le_bytes());
    data[12..14].copy_from_slice(&78u16.to_le_bytes());
    data[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());

    data[16..80].copy_from_slice(sig);
    data[80..112].copy_from_slice(pubkey);
    data[112..190].copy_from_slice(message);

    Instruction {
        program_id: ed25519_prog,
        accounts:   vec![],   // precompile takes no accounts
        data,
    }
}
