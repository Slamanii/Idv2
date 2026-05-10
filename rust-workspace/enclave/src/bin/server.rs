/// enclave-server — HSM boundary process.
///
/// All cryptographic key material lives in SoftHSM2 / hardware HSM via PKCS#11.
/// The ballot-signing Ed25519 key is on SLOT_ROOT and never extracted.
/// Voter credential issuance uses SLOT_VOTER (K_wrap + attestation key on same slot
/// after running: cargo run -p enclave --bin key_ceremony -- --slot 2 --pin <voter-pin>).
///
/// Authenticated routes (HMAC-SHA256 gated):
///   POST /identify  → voter public info from fingerprint
///   POST /register  → signed insert_commitment tx bytes (hex)
///   POST /vote      → signed [ed25519_precompile, ballot::cast] tx bytes (hex)
///
/// Biometric auth is application-layer (NIMC fingerprint lookup).
/// PKCS#11 sessions use operator PINs supplied at startup.
use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};

use enclave::{
    ballot_auth::{authorize_ballot, ballot_message},
    credential::{credential_hash, derive_credential_secret},
    hsm::{HsmContext, LABEL_ED25519_SIGN},
    issuance::{issue, verify_attestation, VoterCredential},
    nullifier,
};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "enclave-server")]
struct Cli {
    #[arg(long, default_value = "dashboard/data/nimc.json")]
    nimc_data: PathBuf,

    /// Relayer keypair JSON — pays Solana transaction fees.
    #[arg(long, default_value = "keys/relayer.json")]
    relayer_keypair: PathBuf,

    /// PIN for the root HSM slot (ballot-sign Ed25519 key).
    #[arg(long, default_value = "1234")]
    root_pin: String,

    /// PIN for the voter HSM slot (K_wrap + attestation key).
    #[arg(long, default_value = "1234")]
    voter_pin: String,

    /// HSM slot index for the root slot (nth initialized token, 0-based).
    /// In production the root key lives on a dedicated hardware token;
    /// for a single-token demo set both --root-slot and --voter-slot to 0.
    #[arg(long, default_value_t = 0)]
    root_slot: usize,

    /// HSM slot index for the voter slot (K_wrap + attestation key).
    #[arg(long, default_value_t = 0)]
    voter_slot: usize,

    /// Where to store per-voter VoterCredential JSON files.
    #[arg(long, default_value = ".creds")]
    cred_dir: PathBuf,

    /// Where to write the HMAC session key (dashboard reads this at startup).
    #[arg(long, default_value = ".keys/enclave-hmac.key")]
    hmac_key_path: PathBuf,

    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    #[arg(long)]
    election_registry_program: String,
    #[arg(long)]
    voter_registry_program: String,
    #[arg(long)]
    ballot_program: String,
    #[arg(long)]
    tally_program: String,

    #[arg(long, default_value = "1")]
    election_id: u64,

    /// State ID of the polling unit this enclave serves (1-37, NIMC ordering).
    /// Votes registered here are counted under this state, regardless of the
    /// voter's NIN-linked home state.
    #[arg(long)]
    polling_state_id: u8,

    /// LGA ID of the polling unit this enclave serves.
    #[arg(long)]
    polling_lga_id: u16,

    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,
}

// ── NIMC record (dummy NIMC database) ────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct NimcRecord {
    nin: String,
    full_name: String,
    #[allow(dead_code)]
    dob: String,
    state_id: u8,
    state_name: String,
    lga_id: u16,
    lga_name: String,
    fingerprint_secret: String,
}

// ── In-memory voter session ───────────────────────────────────────────────────

#[derive(Clone)]
struct VoterSession {
    full_name: String,
    state_id: u8,
    state_name: String,
    lga_id: u16,
    lga_name: String,
    credential_secret: [u8; 32],
    voter_id: [u8; 32],
    leaf_index: Option<u64>,
}

// ── Program IDs ───────────────────────────────────────────────────────────────

struct ProgramIds {
    election_registry: Pubkey,
    voter_registry: Pubkey,
    ballot: Pubkey,
    tally: Pubkey,
}

// ── Shared app state ──────────────────────────────────────────────────────────

struct AppState {
    hmac_key: [u8; 32],
    nimc_by_fp: HashMap<String, NimcRecord>,
    relayer: Keypair,
    rpc: RpcClient,
    pids: ProgramIds,
    election_id: u64,
    root_pin: String,
    voter_pin: String,
    root_slot: usize,
    voter_slot: usize,
    polling_state_id: u8,
    polling_lga_id: u16,
    cred_dir: PathBuf,
    /// credential_hash → VoterSession
    sessions: RwLock<HashMap<[u8; 32], VoterSession>>,
}

// ── Request / response shapes ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct IdentifyReq {
    fingerprint_secret: String,
}

#[derive(Serialize)]
struct IdentifyResp {
    full_name: String,
    state_name: String,
    lga_name: String,
    registered: bool,
}

#[derive(Deserialize)]
struct RegisterReq {
    fingerprint_secret: String,
}

#[derive(Deserialize)]
struct VoteReq {
    fingerprint_secret: String,
    candidate_id: u8,
}

#[derive(Serialize)]
struct SigResp {
    signature: String,
}

// ── HMAC middleware ───────────────────────────────────────────────────────────

async fn hmac_auth(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let ts_str = match headers.get("x-request-ts").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return (StatusCode::UNAUTHORIZED, "missing X-Request-Ts").into_response(),
    };
    let sig_hex = match headers.get("x-hmac-sig").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return (StatusCode::UNAUTHORIZED, "missing X-HMAC-Sig").into_response(),
    };

    let ts: u64 = match ts_str.parse() {
        Ok(v) => v,
        Err(_) => return (StatusCode::UNAUTHORIZED, "bad timestamp").into_response(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.abs_diff(ts) > 30 {
        return (StatusCode::UNAUTHORIZED, "timestamp stale (>30s)").into_response();
    }

    let (parts, body) = request.into_parts();
    let body_bytes: Bytes = match axum::body::to_bytes(body, 1 << 20).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "body read error").into_response(),
    };

    let mut mac: Hmac<sha2::Sha256> = Hmac::new_from_slice(&st.hmac_key).unwrap();
    mac.update(ts_str.as_bytes());
    mac.update(b"\n");
    mac.update(&body_bytes);
    let expected = hex::encode(mac.finalize().into_bytes());

    if sig_hex != expected {
        return (StatusCode::UNAUTHORIZED, "invalid HMAC").into_response();
    }

    next.run(Request::from_parts(parts, axum::body::Body::from(body_bytes)))
        .await
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_identify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<IdentifyReq>,
) -> Response {
    let rec = match st.nimc_by_fp.get(&req.fingerprint_secret) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "fingerprint not found").into_response(),
    };

    let cred = derive_credential_secret(&rec.nin, &rec.fingerprint_secret);
    let key = credential_hash(&cred);
    let voter_id: [u8; 32] = Sha256::digest(rec.nin.as_bytes()).into();

    // Check session first; fall back to disk credential for restart recovery.
    let session_leaf_index = st
        .sessions
        .read()
        .await
        .get(&key)
        .and_then(|s| s.leaf_index);

    let disk_leaf_index = if session_leaf_index.is_none() {
        let cred_path = VoterCredential::path_for(&st.cred_dir, &voter_id);
        VoterCredential::load(&cred_path).ok().and_then(|v| v.leaf_index)
    } else {
        None
    };

    let registered = session_leaf_index.or(disk_leaf_index).is_some();

    let mut sessions = st.sessions.write().await;
    let session = sessions.entry(key).or_insert(VoterSession {
        full_name: rec.full_name.clone(),
        state_id: rec.state_id,
        state_name: rec.state_name.clone(),
        lga_id: rec.lga_id,
        lga_name: rec.lga_name.clone(),
        credential_secret: cred,
        voter_id,
        leaf_index: None,
    });
    // Warm the in-memory session from disk if coming back after a restart.
    if session.leaf_index.is_none() {
        session.leaf_index = disk_leaf_index;
    }

    Json(IdentifyResp {
        full_name: rec.full_name.clone(),
        state_name: rec.state_name.clone(),
        lga_name: rec.lga_name.clone(),
        registered,
    })
    .into_response()
}

async fn handle_register(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Response {
    let rec = match st.nimc_by_fp.get(&req.fingerprint_secret) {
        Some(r) => r.clone(),
        None => return (StatusCode::NOT_FOUND, "fingerprint not found").into_response(),
    };

    let cred = derive_credential_secret(&rec.nin, &rec.fingerprint_secret);
    let key = credential_hash(&cred);
    let voter_id: [u8; 32] = Sha256::digest(rec.nin.as_bytes()).into();

    {
        let sessions = st.sessions.read().await;
        if sessions.get(&key).and_then(|s| s.leaf_index).is_some() {
            return (StatusCode::CONFLICT, "already registered").into_response();
        }
    }

    // Fetch all RPC parameters before blocking on the HSM.
    let leaf_index = match fetch_leaf_count(&st) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("fetch_leaf_count: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "rpc error").into_response();
        }
    };
    // LeafAccount: disc(8) + election_id(8) + index(8) + commitment(32) = 56 bytes.
    let leaf_lamports = match st.rpc.get_minimum_balance_for_rent_exemption(56) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("get_min_balance leaf: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "rpc error").into_response();
        }
    };
    let recent_blockhash = match st.rpc.get_latest_blockhash() {
        Ok(bh) => bh,
        Err(e) => {
            eprintln!("get_latest_blockhash: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "rpc error").into_response();
        }
    };

    // All PKCS#11 and commitment operations are synchronous — run on a blocking thread.
    // Use polling-unit geography, not NIMC home state — the polling unit where
    // the voter registers determines which state/LGA their vote counts under.
    let state_id = st.polling_state_id;
    let lga_id = st.polling_lga_id;
    let eid = st.election_id;
    let voter_pin = st.voter_pin.clone();
    let voter_slot = st.voter_slot;
    let cred_dir = st.cred_dir.clone();

    let commitment_result = tokio::task::block_in_place(|| -> anyhow::Result<[u8; 32]> {
        let ctx = HsmContext::from_env().context("PKCS#11 init")?;
        let session = ctx
            .open_session(voter_slot, &voter_pin)
            .context("open voter session")?;

        let blinding = Scalar::random(&mut OsRng);
        let vcred = issue(&session, &cred, state_id, lga_id, eid, &blinding)
            .context("credential issuance")?;

        let cred_path = VoterCredential::path_for(&cred_dir, &voter_id);
        vcred.save_atomic(&cred_path).context("save credential")?;

        let valid = verify_attestation(&session, &vcred.commitment, eid, &vcred.attestation_mac)
            .context("verify attestation")?;
        session.logout()?;

        if !valid {
            bail!("attestation MAC verification failed — commitment may be tampered");
        }

        Ok(vcred.commitment)
    });

    let commitment = match commitment_result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("register/hsm: {e:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "hsm error").into_response();
        }
    };

    let tx = match build_register_tx(&st, &commitment, recent_blockhash, leaf_lamports, leaf_index) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("build_register_tx: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "tx build failed").into_response();
        }
    };

    let sig = match st.rpc.send_and_confirm_transaction(&tx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("register/broadcast: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "tx broadcast failed").into_response();
        }
    };

    // Persist leaf_index to disk so it survives a restart.
    let cred_path = VoterCredential::path_for(&st.cred_dir, &voter_id);
    if let Ok(mut vcred) = VoterCredential::load(&cred_path) {
        vcred.leaf_index = Some(leaf_index);
        let _ = vcred.save_atomic(&cred_path);
    }

    let mut sessions = st.sessions.write().await;
    let session = sessions.entry(key).or_insert(VoterSession {
        full_name: rec.full_name.clone(),
        state_id: rec.state_id,
        state_name: rec.state_name.clone(),
        lga_id: rec.lga_id,
        lga_name: rec.lga_name.clone(),
        credential_secret: cred,
        voter_id,
        leaf_index: None,
    });
    session.leaf_index = Some(leaf_index);

    Json(SigResp { signature: sig.to_string() }).into_response()
}

async fn handle_vote(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VoteReq>,
) -> Response {
    let rec = match st.nimc_by_fp.get(&req.fingerprint_secret) {
        Some(r) => r.clone(),
        None => return (StatusCode::NOT_FOUND, "fingerprint not found").into_response(),
    };

    let cred = derive_credential_secret(&rec.nin, &rec.fingerprint_secret);
    let key = credential_hash(&cred);
    let voter_id: [u8; 32] = Sha256::digest(rec.nin.as_bytes()).into();

    // Prefer in-memory leaf_index; fall back to disk credential for restart recovery.
    let leaf_index = {
        let sessions = st.sessions.read().await;
        sessions.get(&key).and_then(|s| s.leaf_index)
    };
    let leaf_index = match leaf_index {
        Some(idx) => idx,
        None => {
            let cred_path = VoterCredential::path_for(&st.cred_dir, &voter_id);
            match VoterCredential::load(&cred_path).ok().and_then(|v| v.leaf_index) {
                Some(idx) => idx,
                None => return (StatusCode::PRECONDITION_FAILED, "voter not registered").into_response(),
            }
        }
    };

    // Fetch RPC parameters before the blocking HSM section.
    // BallotAccount::LEN = 88, NullifierAccount::LEN = 1.
    let ballot_lamports = match st.rpc.get_minimum_balance_for_rent_exemption(88) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("get_min_balance ballot: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "rpc error").into_response();
        }
    };
    let null_lamports = match st.rpc.get_minimum_balance_for_rent_exemption(1) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("get_min_balance nullifier: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "rpc error").into_response();
        }
    };
    let recent_blockhash = match st.rpc.get_latest_blockhash() {
        Ok(bh) => bh,
        Err(e) => {
            eprintln!("get_latest_blockhash: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "rpc error").into_response();
        }
    };

    let eid = st.election_id;
    let root_pin = st.root_pin.clone();
    let root_slot = st.root_slot;
    let cred_dir = st.cred_dir.clone();

    // Derive nullifier + load commitment/geography from disk, then sign via HSM.
    // Returns: (sig, authority_pubkey, nullifier, commitment, state_id, lga_id)
    // Geography is loaded from the credential — it was frozen at registration time
    // so the ballot is always counted under the polling unit where the voter enrolled.
    type SignResult = ([u8; 64], [u8; 32], [u8; 32], [u8; 32], u8, u16);
    let sign_result = tokio::task::block_in_place(|| -> anyhow::Result<SignResult> {
        let cred_path = VoterCredential::path_for(&cred_dir, &voter_id);
        let vcred = VoterCredential::load(&cred_path)
            .context("load voter credential — was registration confirmed on-chain?")?;

        let nullifier_bytes = nullifier::derive(&cred, eid);

        let ctx = HsmContext::from_env().context("PKCS#11 init")?;
        let root_session = ctx
            .open_session(root_slot, &root_pin)
            .context("open root session")?;

        let priv_h = root_session
            .require_priv_by_label(LABEL_ED25519_SIGN)
            .context("ballot-sign private key not found — run key ceremony")?;
        let pub_h = root_session
            .require_pub_by_label(LABEL_ED25519_SIGN)
            .context("ballot-sign public key not found — run key ceremony")?;

        let auth = authorize_ballot(&root_session, priv_h, pub_h, &nullifier_bytes, &vcred.commitment)
            .context("authorize_ballot (HSM sign)")?;

        root_session.logout()?;

        Ok((auth.signature, auth.authority_pubkey, nullifier_bytes, vcred.commitment, vcred.state_id, vcred.lga_id))
    });

    let (hsm_sig, authority_pk, nullifier_bytes, commitment, state_id, lga_id) = match sign_result {
        Ok(t) => t,
        Err(e) => {
            eprintln!("vote/hsm: {e:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "hsm error").into_response();
        }
    };

    let msg = ballot_message(&nullifier_bytes, &commitment);

    let tx = match build_vote_tx(
        &st,
        leaf_index,
        &nullifier_bytes,
        req.candidate_id,
        state_id,
        lga_id,
        &hsm_sig,
        &authority_pk,
        &msg,
        recent_blockhash,
        ballot_lamports,
        null_lamports,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("build_vote_tx: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "tx build failed").into_response();
        }
    };

    let sig = match st.rpc.send_and_confirm_transaction(&tx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vote/broadcast: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "tx broadcast failed").into_response();
        }
    };

    // Update in-memory session if it wasn't populated (restart recovery path).
    {
        let mut sessions = st.sessions.write().await;
        if let Some(session) = sessions.get_mut(&key) {
            if session.leaf_index.is_none() {
                session.leaf_index = Some(leaf_index);
            }
        }
    }

    Json(SigResp { signature: sig.to_string() }).into_response()
}

// ── PDA derivation ────────────────────────────────────────────────────────────

fn election_pda(pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"election", &eid.to_le_bytes()], pid)
}

fn voter_registry_pda(pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"voter_registry", &eid.to_le_bytes()], pid)
}

fn leaf_pda(pid: &Pubkey, eid: u64, idx: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"leaf", &eid.to_le_bytes(), &idx.to_le_bytes()], pid)
}

fn ballot_pda(pid: &Pubkey, eid: u64, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"ballot", &eid.to_le_bytes(), nullifier.as_ref()], pid)
}

fn nullifier_pda(pid: &Pubkey, eid: u64, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", &eid.to_le_bytes(), nullifier.as_ref()], pid)
}

fn tally_pda(pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"tally", &eid.to_le_bytes()], pid)
}

// ── RPC helper ────────────────────────────────────────────────────────────────

fn fetch_leaf_count(st: &AppState) -> anyhow::Result<u64> {
    let (vr_pda, _) = voter_registry_pda(&st.pids.voter_registry, st.election_id);
    let acct = st
        .rpc
        .get_account_with_commitment(&vr_pda, CommitmentConfig::confirmed())
        .context("get voter_registry account")?
        .value
        .context("voter_registry account not found")?;
    // VoterRegistryAccount layout: disc(8) + eid(8) + root(32) + leaf_count(8)
    if acct.data.len() < 56 {
        bail!("voter_registry account too short");
    }
    Ok(u64::from_le_bytes(acct.data[48..56].try_into().unwrap()))
}

// ── Transaction builders ──────────────────────────────────────────────────────

fn build_register_tx(
    st: &AppState,
    commitment: &[u8; 32],
    recent_blockhash: solana_sdk::hash::Hash,
    leaf_lamports: u64,
    leaf_index: u64,
) -> anyhow::Result<Transaction> {
    let eid = st.election_id;

    let (election_acct, _) = election_pda(&st.pids.election_registry, eid);
    let (vr_pda, _) = voter_registry_pda(&st.pids.voter_registry, eid);
    let (leaf_acct, leaf_bump) = leaf_pda(&st.pids.voter_registry, eid, leaf_index);

    let relayer_pk = st.relayer.pubkey();
    let clock: Pubkey = "SysvarC1ock11111111111111111111111111111111".parse().unwrap();
    let system = solana_sdk_ids::system_program::ID;

    // insert_commitment: tag(1) + eid(8) + commitment(32) + leaf_lamports(8) + leaf_bump(1) = 50
    let mut data = vec![0u8; 50]; // tag byte = 0
    data[1..9].copy_from_slice(&eid.to_le_bytes());
    data[9..41].copy_from_slice(commitment);
    data[41..49].copy_from_slice(&leaf_lamports.to_le_bytes());
    data[49] = leaf_bump;

    let ix = Instruction {
        program_id: st.pids.voter_registry,
        accounts: vec![
            AccountMeta::new(relayer_pk, true),
            AccountMeta::new_readonly(election_acct, false),
            AccountMeta::new(vr_pda, false),
            AccountMeta::new(leaf_acct, false),
            AccountMeta::new_readonly(clock, false),
            AccountMeta::new_readonly(system, false),
        ],
        data,
    };

    Ok(Transaction::new_signed_with_payer(&[ix], Some(&relayer_pk), &[&st.relayer], recent_blockhash))
}

#[allow(clippy::too_many_arguments)]
fn build_vote_tx(
    st: &AppState,
    leaf_index: u64,
    nullifier: &[u8; 32],
    candidate_id: u8,
    state_id: u8,
    lga_id: u16,
    hsm_sig: &[u8; 64],
    authority_pk: &[u8; 32],
    ballot_msg: &[u8; 78],
    recent_blockhash: solana_sdk::hash::Hash,
    ballot_lamports: u64,
    null_lamports: u64,
) -> anyhow::Result<Transaction> {
    let eid = st.election_id;

    let (election_acct, _) = election_pda(&st.pids.election_registry, eid);
    let (vr_pda, _) = voter_registry_pda(&st.pids.voter_registry, eid);
    let (leaf_acct, _) = leaf_pda(&st.pids.voter_registry, eid, leaf_index);
    let (ballot_acct, ballot_bump) = ballot_pda(&st.pids.ballot, eid, nullifier);
    let (null_acct, null_bump) = nullifier_pda(&st.pids.ballot, eid, nullifier);
    let (tally_acct, _) = tally_pda(&st.pids.tally, eid);

    let relayer_pk = st.relayer.pubkey();
    let clock: Pubkey = "SysvarC1ock11111111111111111111111111111111".parse().unwrap();
    let ixs_sysvar: Pubkey = "Sysvar1nstructions1111111111111111111111111".parse().unwrap();
    let ed25519_prog: Pubkey = "Ed25519SigVerify111111111111111111111111111".parse().unwrap();
    let system = solana_sdk_ids::system_program::ID;

    // ix[0]: native Ed25519 precompile (190-byte data, no accounts).
    let ed25519_ix = Instruction {
        program_id: ed25519_prog,
        accounts: vec![],
        data: build_ed25519_precompile_data(authority_pk, hsm_sig, ballot_msg),
    };

    // ix[1]: ballot::cast — tag(1) + 166 bytes of payload.
    // Offsets below are on-chain offsets + 1 (byte 0 is the tag).
    let mut cast_data = vec![0u8; 167]; // tag = 0
    cast_data[1..9].copy_from_slice(&eid.to_le_bytes());            // OFF_EID        = 0
    cast_data[9..17].copy_from_slice(&leaf_index.to_le_bytes());    // OFF_LEAF_INDEX = 8
    cast_data[17..49].copy_from_slice(nullifier);                   // OFF_NULLIFIER  = 16
    cast_data[49] = candidate_id;                                   // OFF_CANDIDATE_ID = 48
    cast_data[50] = state_id;                                       // OFF_STATE_ID   = 49
    cast_data[51..53].copy_from_slice(&lga_id.to_le_bytes());       // OFF_LGA_ID     = 50
    cast_data[53..61].copy_from_slice(&ballot_lamports.to_le_bytes()); // OFF_BALLOT_LAMPS = 52
    cast_data[61..69].copy_from_slice(&null_lamports.to_le_bytes()); // OFF_NULL_LAMPS = 60
    cast_data[69] = ballot_bump;                                    // OFF_BALLOT_BUMP = 68
    cast_data[70] = null_bump;                                      // OFF_NULL_BUMP  = 69
    cast_data[71..135].copy_from_slice(hsm_sig);                    // OFF_HSM_SIG    = 70
    cast_data[135..167].copy_from_slice(authority_pk);              // OFF_AUTHORITY_PK = 134

    let cast_ix = Instruction {
        program_id: st.pids.ballot,
        accounts: vec![
            AccountMeta::new(relayer_pk, true),              // [0]  relayer
            AccountMeta::new_readonly(election_acct, false), // [1]  election_account
            AccountMeta::new_readonly(vr_pda, false),        // [2]  voter_registry
            AccountMeta::new_readonly(leaf_acct, false),     // [3]  leaf_account
            AccountMeta::new(ballot_acct, false),            // [4]  ballot_account (new)
            AccountMeta::new(null_acct, false),              // [5]  nullifier_account (new)
            AccountMeta::new_readonly(clock, false),         // [6]  clock_sysvar
            AccountMeta::new_readonly(system, false),        // [7]  system_program
            AccountMeta::new(tally_acct, false),             // [8]  tally_account
            AccountMeta::new_readonly(st.pids.tally, false), // [9]  tally_program
            AccountMeta::new_readonly(ixs_sysvar, false),    // [10] ixs_sysvar
        ],
        data: cast_data,
    };

    Ok(Transaction::new_signed_with_payer(
        &[ed25519_ix, cast_ix],
        Some(&relayer_pk),
        &[&st.relayer],
        recent_blockhash,
    ))
}

/// Build 190-byte Ed25519 precompile instruction data for a 78-byte ballot message.
///
/// Per Solana native precompile spec:
///   header (16 bytes): count=1, pad=0, sig_off=16, sig_ix=0xFFFF,
///                      pk_off=80, pk_ix=0xFFFF, msg_off=112, msg_len=78, msg_ix=0xFFFF
///   sig @ 16..80, pk @ 80..112, msg @ 112..190
fn build_ed25519_precompile_data(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8; 78]) -> Vec<u8> {
    let mut d = vec![0u8; 190];
    d[0] = 1;
    d[1] = 0;
    d[2..4].copy_from_slice(&16u16.to_le_bytes());
    d[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    d[6..8].copy_from_slice(&80u16.to_le_bytes());
    d[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
    d[10..12].copy_from_slice(&112u16.to_le_bytes());
    d[12..14].copy_from_slice(&78u16.to_le_bytes());
    d[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());
    d[16..80].copy_from_slice(sig);
    d[80..112].copy_from_slice(pk);
    d[112..190].copy_from_slice(msg);
    d
}

// ── Startup helpers ───────────────────────────────────────────────────────────

fn load_keypair(path: &PathBuf) -> anyhow::Result<Keypair> {
    let bytes: Vec<u8> = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("read {path:?}"))?,
    )
    .context("parse keypair JSON — expected array of 64 integers")?;
    if bytes.len() < 32 {
        anyhow::bail!("keypair too short: {} bytes", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    Ok(Keypair::new_from_array(arr))
}

fn gen_and_write_hmac_key(path: &PathBuf) -> anyhow::Result<[u8; 32]> {
    let key: [u8; 32] = rand::random();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::File::create(path)
        .with_context(|| format!("create {path:?}"))?
        .write_all(&key)?;
    Ok(key)
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load NIMC records indexed by fingerprint_secret.
    let nimc_records: Vec<NimcRecord> = serde_json::from_str(
        &fs::read_to_string(&cli.nimc_data)
            .with_context(|| format!("read {:?}", cli.nimc_data))?,
    )
    .context("parse NIMC JSON")?;
    let nimc_by_fp: HashMap<String, NimcRecord> = nimc_records
        .into_iter()
        .map(|r| (r.fingerprint_secret.clone(), r))
        .collect();
    println!("NIMC: {} records loaded", nimc_by_fp.len());

    // Sanity-check: confirm HSM is reachable and ballot-sign key exists.
    tokio::task::block_in_place(|| -> anyhow::Result<()> {
        let ctx = HsmContext::from_env().context("PKCS#11 init")?;
        let session = ctx
            .open_session(cli.root_slot, &cli.root_pin)
            .context("open root session — check SOFTHSM2_LIB and run key ceremony")?;
        let pub_h = session
            .require_pub_by_label(LABEL_ED25519_SIGN)
            .context("ballot-sign key missing — run: cargo run -p enclave --bin key_ceremony")?;
        let authority_pubkey = session.get_ed25519_pubkey(pub_h)?;
        session.logout()?;
        println!("HSM OK — aggregation pubkey: {}", hex::encode(authority_pubkey));
        Ok(())
    })?;

    fs::create_dir_all(&cli.cred_dir)?;

    let hmac_key = gen_and_write_hmac_key(&cli.hmac_key_path)?;
    println!("HMAC key → {:?}", cli.hmac_key_path);

    let relayer = load_keypair(&cli.relayer_keypair)?;
    println!("relayer: {}", relayer.pubkey());

    let state = Arc::new(AppState {
        hmac_key,
        nimc_by_fp,
        relayer,
        rpc: RpcClient::new_with_commitment(cli.rpc_url.clone(), CommitmentConfig::confirmed()),
        pids: ProgramIds {
            election_registry: cli.election_registry_program.parse()?,
            voter_registry: cli.voter_registry_program.parse()?,
            ballot: cli.ballot_program.parse()?,
            tally: cli.tally_program.parse()?,
        },
        election_id: cli.election_id,
        root_pin: cli.root_pin,
        voter_pin: cli.voter_pin,
        root_slot: cli.root_slot,
        voter_slot: cli.voter_slot,
        polling_state_id: cli.polling_state_id,
        polling_lga_id: cli.polling_lga_id,
        cred_dir: cli.cred_dir,
        sessions: RwLock::new(HashMap::new()),
    });

    let protected = Router::new()
        .route("/identify", post(handle_identify))
        .route("/register", post(handle_register))
        .route("/vote", post(handle_vote))
        .layer(middleware::from_fn_with_state(state.clone(), hmac_auth));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(protected)
        .with_state(state);

    println!("enclave-server on {}", cli.bind);
    axum::serve(tokio::net::TcpListener::bind(cli.bind).await?, app).await?;
    Ok(())
}
