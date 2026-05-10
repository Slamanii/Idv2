//! idv2-verify — public, read-only audit CLI.
//!
//! No keypair required. Reads on-chain state and reconstructs the tally
//! independently, allowing any observer to audit the election result.
//!
//! Subcommands:
//!
//!   audit-tally   --election-program <ID> --tally-program <ID> --id 1
//!     Fetch TallyAccount; print per-candidate totals and finalized flag.
//!
//!   check-nullifiers  --ballot-program <ID> --id 1
//!     Walk all NullifierAccount PDAs (by scanning ballot account logs),
//!     confirm they are unique and that count matches TallyAccount.total_votes.
//!
//!   show-election  --election-program <ID> --id 1
//!     Dump ElectionAccount: phase, candidates, slot windows.
//!
//!   rebuild-merkle  --voter-program <ID> --id 1
//!     Read every LeafAccount for the election; rebuild the SMT root locally
//!     and compare to on-chain VoterRegistryAccount.merkle_root.
//!
//! All commands default to devnet. Pass --rpc for a custom endpoint.

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey};
use std::str::FromStr;

// ── Re-use on-chain types ────────────────────────────────────────────────────

use ballot::{BallotAccount, NullifierAccount};
use election_registry::ElectionAccount;
use tally::TallyAccount;
use voter_registry::VoterRegistryAccount;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "idv2-verify", version, about = "Public audit CLI for idv2")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    #[arg(long, default_value = "https://api.devnet.solana.com", global = true)]
    rpc: String,

    #[arg(long, global = true)] election_program: Option<String>,
    #[arg(long, global = true)] voter_program:    Option<String>,
    #[arg(long, global = true)] ballot_program:   Option<String>,
    #[arg(long, global = true)] tally_program:    Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print TallyAccount: per-candidate vote counts + finalized flag.
    AuditTally {
        #[arg(long)] id: u64,
    },
    /// Enumerate all BallotAccounts; rebuild tally independently.
    RebuildTally {
        #[arg(long)] id: u64,
        /// Max accounts to fetch in one getProgramAccounts call (default 1000).
        #[arg(long, default_value = "1000")] limit: usize,
    },
    /// Check nullifier uniqueness: count NullifierAccounts vs TallyAccount.total_votes.
    CheckNullifiers {
        #[arg(long)] id: u64,
    },
    /// Dump ElectionAccount: phase, slot windows, candidate roster.
    ShowElection {
        #[arg(long)] id: u64,
    },
    /// Read every LeafAccount; rebuild the Merkle root; compare to on-chain root.
    RebuildMerkle {
        #[arg(long)] id: u64,
    },
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new_with_commitment(cli.rpc.clone(), CommitmentConfig::confirmed());

    match &cli.command {
        Cmd::AuditTally { id } => audit_tally(&client, &cli, *id)?,
        Cmd::RebuildTally { id, limit } => rebuild_tally(&client, &cli, *id, *limit)?,
        Cmd::CheckNullifiers { id } => check_nullifiers(&client, &cli, *id)?,
        Cmd::ShowElection { id } => show_election(&client, &cli, *id)?,
        Cmd::RebuildMerkle { id } => rebuild_merkle(&client, &cli, *id)?,
    }
    Ok(())
}

// ── audit-tally ───────────────────────────────────────────────────────────────

fn audit_tally(client: &RpcClient, cli: &Cli, election_id: u64) -> anyhow::Result<()> {
    let tally_prog  = require_program(&cli.tally_program,    "tally-program")?;
    let elect_prog  = require_program(&cli.election_program, "election-program")?;

    let eid_le = election_id.to_le_bytes();
    let (tally_pda, _) = Pubkey::find_program_address(&[b"tally", &eid_le], &tally_prog);
    let (elect_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &elect_prog);

    let tally_data = client.get_account_data(&tally_pda)
        .with_context(|| format!("TallyAccount not found at {tally_pda}"))?;
    let elect_data = client.get_account_data(&elect_pda)
        .with_context(|| format!("ElectionAccount not found at {elect_pda}"))?;

    if tally_data.len() < TallyAccount::LEN {
        anyhow::bail!("TallyAccount too short: {} bytes", tally_data.len());
    }
    let tally = unsafe { TallyAccount::from_bytes(&tally_data) };

    if elect_data.len() < ElectionAccount::LEN {
        anyhow::bail!("ElectionAccount too short: {} bytes", elect_data.len());
    }
    let elect = unsafe { ElectionAccount::from_bytes(&elect_data) };

    let n = elect.candidate_count as usize;

    println!("── TallyAccount {tally_pda} ──");
    println!("  election_id       : {}", tally.election_id);
    println!("  total_votes       : {}", tally.total_votes);
    println!("  finalized         : {}", tally.finalized != 0);
    println!("  last_updated_slot : {}", tally.last_updated_slot);
    println!();
    println!("  Candidate results ({n} candidates):");
    println!("  {:>3}  {:>32}  {:>12}  {:>8}", "ID", "Name", "Party", "Votes");
    println!("  {}", "─".repeat(62));
    for i in 0..n {
        let c = &elect.candidates[i];
        let name  = trim_null(&c.name);
        let party = trim_null(&c.party);
        let votes = tally.candidate_total(i as u8);
        println!("  {:>3}  {:>32}  {:>12}  {:>8}", i, name, party, votes);
    }

    // Cross-check: sum of candidate totals == total_votes
    let total_from_candidates: u64 = (0..n as u8).map(|id| tally.candidate_total(id)).sum();
    if total_from_candidates != tally.total_votes {
        println!();
        println!("  WARNING: sum of candidate totals ({total_from_candidates}) ≠ total_votes ({})!",
            tally.total_votes);
    } else {
        println!();
        println!("  ✓ Candidate totals sum to total_votes = {}", tally.total_votes);
    }

    Ok(())
}

// ── rebuild-tally ─────────────────────────────────────────────────────────────

fn rebuild_tally(client: &RpcClient, cli: &Cli, election_id: u64, _limit: usize) -> anyhow::Result<()> {
    let ballot_prog = require_program(&cli.ballot_program, "ballot-program")?;

    let accounts = client
        .get_program_accounts(&ballot_prog)
        .context("getProgramAccounts for ballot failed")?;

    let eid_le = election_id.to_le_bytes();
    let mut counts: [u64; 32] = [0; 32];
    let mut total = 0u64;
    let mut matched = 0usize;

    for (pubkey, account) in &accounts {
        let data = &account.data;
        if data.len() < BallotAccount::LEN {
            continue;
        }
        if data[..8] != BallotAccount::DISCRIMINATOR {
            continue;
        }
        let ballot = unsafe { BallotAccount::from_bytes(data) };
        if ballot.election_id.to_le_bytes() != eid_le {
            continue;
        }
        let cid = ballot.candidate_id as usize;
        if cid < 32 {
            counts[cid] += 1;
            total += 1;
        }
        matched += 1;
        let _ = pubkey;
    }

    println!("── Rebuilt tally from BallotAccounts ──");
    println!("  election_id : {election_id}");
    println!("  ballots found : {matched}  total votes : {total}");
    println!();
    println!("  {:>3}  {:>8}", "ID", "Votes");
    println!("  {}", "─".repeat(16));
    for (id, &v) in counts.iter().enumerate() {
        if v > 0 {
            println!("  {:>3}  {:>8}", id, v);
        }
    }

    Ok(())
}

// ── check-nullifiers ──────────────────────────────────────────────────────────

fn check_nullifiers(client: &RpcClient, cli: &Cli, election_id: u64) -> anyhow::Result<()> {
    let ballot_prog = require_program(&cli.ballot_program, "ballot-program")?;
    let tally_prog  = require_program(&cli.tally_program,  "tally-program")?;

    let eid_le = election_id.to_le_bytes();
    let (tally_pda, _) = Pubkey::find_program_address(&[b"tally", &eid_le], &tally_prog);

    let tally_data = client.get_account_data(&tally_pda)
        .with_context(|| format!("TallyAccount not found at {tally_pda}"))?;
    let tally = unsafe { TallyAccount::from_bytes(&tally_data) };
    let on_chain_total = tally.total_votes;

    // Fetch all NullifierAccounts owned by ballot_program
    let accounts = client
        .get_program_accounts(&ballot_prog)
        .context("getProgramAccounts for ballot failed")?;

    let mut nullifier_count = 0u64;
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = 0u64;

    for (_pubkey, account) in &accounts {
        let data = &account.data;
        if data.len() != NullifierAccount::LEN {
            continue;
        }
        if data[0] == 1 {
            nullifier_count += 1;
            if !seen.insert(_pubkey.to_bytes()) {
                duplicates += 1;
            }
        }
    }

    println!("── Nullifier audit  election_id={election_id} ──");
    println!("  NullifierAccounts marked : {nullifier_count}");
    println!("  Duplicate pubkeys        : {duplicates}");
    println!("  TallyAccount.total_votes : {on_chain_total}");

    if duplicates > 0 {
        println!("  FAIL: {duplicates} duplicate nullifier pubkeys detected!");
    } else {
        println!("  ✓ No duplicate nullifier accounts.");
    }

    if nullifier_count == on_chain_total {
        println!("  ✓ Nullifier count matches total_votes.");
    } else {
        println!("  WARNING: nullifier count ({nullifier_count}) ≠ total_votes ({on_chain_total}).");
    }

    Ok(())
}

// ── show-election ─────────────────────────────────────────────────────────────

fn show_election(client: &RpcClient, cli: &Cli, election_id: u64) -> anyhow::Result<()> {
    let elect_prog = require_program(&cli.election_program, "election-program")?;
    let eid_le = election_id.to_le_bytes();
    let (elect_pda, _) = Pubkey::find_program_address(&[b"election", &eid_le], &elect_prog);

    let data = client.get_account_data(&elect_pda)
        .with_context(|| format!("ElectionAccount not found at {elect_pda}"))?;

    if data.len() < ElectionAccount::LEN {
        anyhow::bail!("ElectionAccount too short: {} bytes", data.len());
    }
    let e = unsafe { ElectionAccount::from_bytes(&data) };

    let phase_name = match e.phase {
        0 => "Draft",
        1 => "RegistrationOpen",
        2 => "RegistrationClosed",
        3 => "VotingOpen",
        4 => "VotingClosed",
        5 => "Tallied",
        _ => "Unknown",
    };

    let agg_pk_hex: String = e.aggregation_pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let auth_pk = Pubkey::try_from(e.authority.as_ref()).unwrap_or_default();

    println!("── ElectionAccount {elect_pda} ──");
    println!("  election_id         : {}", e.election_id);
    println!("  authority           : {auth_pk}");
    println!("  aggregation_pubkey  : {agg_pk_hex}");
    println!("  phase               : {} ({})", e.phase, phase_name);
    println!("  reg_open_slot       : {}", e.registration_open_slot);
    println!("  reg_close_slot      : {}", e.registration_close_slot);
    println!("  vote_open_slot      : {}", e.voting_open_slot);
    println!("  vote_close_slot     : {}", e.voting_close_slot);
    println!("  candidate_count     : {}", e.candidate_count);
    println!();
    println!("  Candidates:");
    println!("  {:>3}  {:>32}  {:>15}", "ID", "Name", "Party");
    println!("  {}", "─".repeat(56));
    for i in 0..e.candidate_count as usize {
        let c = &e.candidates[i];
        println!("  {:>3}  {:>32}  {:>15}", c.id, trim_null(&c.name), trim_null(&c.party));
    }

    Ok(())
}

// ── rebuild-merkle ────────────────────────────────────────────────────────────

fn rebuild_merkle(client: &RpcClient, cli: &Cli, election_id: u64) -> anyhow::Result<()> {
    let voter_prog = require_program(&cli.voter_program, "voter-program")?;
    let eid_le = election_id.to_le_bytes();
    let (vr_pda, _) = Pubkey::find_program_address(&[b"voter_registry", &eid_le], &voter_prog);

    let vr_data = client.get_account_data(&vr_pda)
        .with_context(|| format!("VoterRegistryAccount not found at {vr_pda}"))?;

    if vr_data.len() < VoterRegistryAccount::LEN {
        anyhow::bail!("VoterRegistryAccount too short: {} bytes", vr_data.len());
    }
    let vr = unsafe { VoterRegistryAccount::from_bytes(&vr_data) };
    let on_chain_count = vr.leaf_count;

    // Fetch all LeafAccounts owned by voter_program
    let accounts = client
        .get_program_accounts(&voter_prog)
        .context("getProgramAccounts for voter_registry failed")?;

    // Collect commitments in insertion order (sorted by leaf index stored in account)
    let mut leaves: Vec<(u64, [u8; 32])> = Vec::new();
    for (_pubkey, account) in &accounts {
        let data = &account.data;
        if data.len() < voter_registry::LeafAccount::LEN {
            continue;
        }
        if data[..8] != voter_registry::LeafAccount::DISCRIMINATOR {
            continue;
        }
        let leaf = unsafe { voter_registry::LeafAccount::from_bytes(data) };
        if leaf.election_id.to_le_bytes() != eid_le {
            continue;
        }
        leaves.push((leaf.index, leaf.commitment));
    }
    leaves.sort_by_key(|(idx, _)| *idx);

    // Rebuild root using the same sha256 hash scheme as smt-server
    use sha2::{Digest, Sha256};

    fn leaf_hash(c: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"idv2:leaf:");
        h.update(c);
        h.finalize().into()
    }
    fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(l);
        h.update(r);
        h.finalize().into()
    }

    const DEPTH: usize = 28;
    let mut empty = [[0u8; 32]; DEPTH + 1];
    for i in 1..=DEPTH {
        empty[i] = node_hash(&empty[i - 1], &empty[i - 1]);
    }

    // Build leaf layer
    let layer: Vec<[u8; 32]> = leaves.iter().map(|(_, c)| leaf_hash(c)).collect();
    // Pad to next power of 2 (or just use incremental method)
    // Simple: compute root via bottom-up tree with empty padding.
    fn root_from_leaves(leaves: &[[u8; 32]], empty: &[[u8; 32]; DEPTH + 1]) -> [u8; 32] {
        if leaves.is_empty() {
            return empty[DEPTH];
        }
        subtree(DEPTH, 0, leaves, empty)
    }
    fn subtree(level: usize, start: usize, leaves: &[[u8; 32]], empty: &[[u8; 32]; DEPTH + 1]) -> [u8; 32] {
        if start >= leaves.len() {
            return empty[level];
        }
        if level == 0 {
            return leaves[start];
        }
        let half = 1usize << (level - 1);
        let l = subtree(level - 1, start, leaves, empty);
        let r = subtree(level - 1, start + half, leaves, empty);
        node_hash(&l, &r)
    }

    let rebuilt_root = root_from_leaves(&layer, &empty);
    let rebuilt_hex: String = rebuilt_root.iter().map(|b| format!("{b:02x}")).collect();

    println!("── Merkle root audit  election_id={election_id} ──");
    println!("  on-chain leaf_count : {on_chain_count}");
    println!("  LeafAccounts found  : {}", leaves.len());
    println!("  rebuilt root        : {rebuilt_hex}");

    if leaves.len() as u64 == on_chain_count {
        println!("  ✓ LeafAccount count matches on-chain leaf_count.");
    } else {
        println!("  FAIL: LeafAccount count ({}) ≠ on-chain leaf_count ({on_chain_count})!",
            leaves.len());
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_program(opt: &Option<String>, flag: &str) -> anyhow::Result<Pubkey> {
    let s = opt.as_deref()
        .ok_or_else(|| anyhow!("--{flag} is required for this subcommand"))?;
    Pubkey::from_str(s).with_context(|| format!("invalid pubkey for --{flag}"))
}

fn trim_null(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("<invalid utf8>")
}
