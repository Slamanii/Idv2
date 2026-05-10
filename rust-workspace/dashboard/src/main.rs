/// dashboard-server
///
/// Routes:
///   GET  /                    → choropleth observer map
///   GET  /booth/:unit_id      → booth UI locked to a polling unit
///   GET  /ws                  → WebSocket: live tally updates
///   GET  /api/tally           → current tally JSON
///   GET  /api/candidates      → candidate id / name / party list
///   GET  /api/polling-units   → list of configured polling unit IDs + names
///   POST /api/identify        → proxy to enclave /identify  (body: polling_unit + fingerprint)
///   POST /api/register        → proxy to enclave /register; enclave builds+broadcasts the tx
///   POST /api/vote            → proxy to enclave /vote; enclave builds+broadcasts the tx
use tower_http::services::ServeDir;

use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{broadcast, RwLock};

use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

// ── Polling unit config ───────────────────────────────────────────────────────

#[derive(Clone)]
struct PollingUnitConfig {
    display_name: String,
    url: String,
    hmac_key: [u8; 32],
}

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "dashboard-server")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// Polling unit spec: id|display_name|url|hmac_key_path  (repeat for each unit)
    #[arg(long = "polling-unit", value_name = "SPEC", required = true)]
    polling_units: Vec<String>,

    #[arg(long)]
    ballot_program: String,

    #[arg(long)]
    voter_registry_program: String,

    #[arg(long, default_value = "1")]
    election_id: u64,

    /// Candidate names in candidate_id order (comma-separated).
    #[arg(long, default_value = "Candidate A,Candidate B,Candidate C")]
    candidate_names: String,

    /// Candidate party names in candidate_id order (comma-separated).
    #[arg(long, default_value = "Party A,Party B,Party C")]
    candidate_parties: String,

    #[arg(long, default_value = "dashboard/data")]
    data_dir: PathBuf,

    #[arg(long, default_value = "0.0.0.0:3000")]
    bind: SocketAddr,
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct TallyState {
    totals: Vec<u64>,
    by_state: HashMap<u8, Vec<u64>>,
}

impl TallyState {
    fn new(n: usize) -> Self {
        Self { totals: vec![0; n], by_state: HashMap::new() }
    }
}

struct AppState {
    rpc: RpcClient,
    enclaves: HashMap<String, PollingUnitConfig>,
    polling_unit_list: Vec<(String, String)>, // (id, display_name) ordered
    http: reqwest::Client,
    ballot_pid: Pubkey,
    voter_registry_pid: Pubkey,
    election_id: u64,
    candidate_names: Vec<String>,   // full names, booth only
    candidate_parties: Vec<String>, // party names, tally/observer
    tally: RwLock<TallyState>,
    ws_tx: broadcast::Sender<String>,
}

// ── API shapes ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct IdentifyReq {
    polling_unit: String,
    fingerprint_secret: String,
}

#[derive(Serialize, Deserialize)]
struct IdentifyResp {
    full_name: String,
    state_name: String,
    lga_name: String,
    registered: bool,
}

#[derive(Deserialize)]
struct RegisterReq {
    polling_unit: String,
    fingerprint_secret: String,
}

#[derive(Deserialize)]
struct VoteReq {
    polling_unit: String,
    fingerprint_secret: String,
    candidate_id: u8,
}

#[derive(Serialize)]
struct TxResult {
    signature: String,
}

/// IMPORTANT: `candidates` field = party names (not candidate names) — keeps payload small
#[derive(Serialize)]
struct TallySnapshot {
    candidates: Vec<String>, // party names for observer map legend
    totals: Vec<u64>,
    by_state: HashMap<String, Vec<u64>>,
}

#[derive(Serialize)]
struct CandidateInfo {
    id: usize,
    name: String,
    party: String,
}

#[derive(Serialize)]
struct PollingUnitInfo {
    id: String,
    name: String,
}

// ── Enclave proxy helper ──────────────────────────────────────────────────────

async fn call_enclave<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
    st: &AppState,
    unit_id: &str,
    path: &str,
    body: &Req,
) -> anyhow::Result<Resp> {
    let cfg = st
        .enclaves
        .get(unit_id)
        .ok_or_else(|| anyhow::anyhow!("unknown polling unit: {unit_id}"))?;

    let body_bytes = serde_json::to_vec(body)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let ts_str = ts.to_string();

    let mut mac: Hmac<Sha256> = Hmac::new_from_slice(&cfg.hmac_key).unwrap();
    mac.update(ts_str.as_bytes());
    mac.update(b"\n");
    mac.update(&body_bytes);
    let sig = hex::encode(mac.finalize().into_bytes());

    let url = format!("{}{path}", cfg.url);
    let resp = st
        .http
        .post(&url)
        .header("content-type", "application/json")
        .header("x-request-ts", &ts_str)
        .header("x-hmac-sig", &sig)
        .body(body_bytes)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("enclave {path} → {status}: {text}");
    }
    serde_json::from_str(&text).context("decode enclave response")
}

// ── Route handlers ────────────────────────────────────────────────────────────

fn err_json(status: StatusCode, e: anyhow::Error) -> Response {
    (status, Json(serde_json::json!({"error": format!("{e:#}")}))).into_response()
}

async fn handle_root() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn handle_booth_unit(
    Path(unit_id): Path<String>,
    State(st): State<Arc<AppState>>,
) -> Response {
    if !st.enclaves.contains_key(&unit_id) {
        let valid: Vec<&str> = st.polling_unit_list.iter().map(|(id, _)| id.as_str()).collect();
        let msg = format!(
            "404 — Unknown polling unit: {unit_id:?}\nValid units: {}",
            valid.join(", ")
        );
        return (StatusCode::NOT_FOUND, msg).into_response();
    }
    Html(include_str!("../static/booth.html")).into_response()
}

async fn handle_polling_units(State(st): State<Arc<AppState>>) -> Json<Vec<PollingUnitInfo>> {
    Json(
        st.polling_unit_list
            .iter()
            .map(|(id, name)| PollingUnitInfo { id: id.clone(), name: name.clone() })
            .collect(),
    )
}

async fn handle_candidates(State(st): State<Arc<AppState>>) -> Json<Vec<CandidateInfo>> {
    Json(
        st.candidate_names
            .iter()
            .zip(st.candidate_parties.iter())
            .enumerate()
            .map(|(i, (name, party))| CandidateInfo {
                id: i,
                name: name.clone(),
                party: party.clone(),
            })
            .collect(),
    )
}

async fn handle_tally(State(st): State<Arc<AppState>>) -> Json<TallySnapshot> {
    let t = st.tally.read().await;
    Json(TallySnapshot {
        candidates: st.candidate_parties.clone(),
        totals: t.totals.clone(),
        by_state: t.by_state.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
    })
}

async fn handle_ws(ws: WebSocketUpgrade, State(st): State<Arc<AppState>>) -> Response {
    ws.on_upgrade(move |socket| ws_handler(socket, st))
}

async fn ws_handler(mut socket: WebSocket, st: Arc<AppState>) {
    {
        let t = st.tally.read().await;
        let snap = serde_json::json!({
            "type": "tally_update",
            "candidates": st.candidate_parties,
            "totals": t.totals,
            "by_state": t.by_state.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<HashMap<String, Vec<u64>>>(),
        });
        let _ = socket.send(WsMessage::Text(snap.to_string())).await;
    }

    let mut rx = st.ws_tx.subscribe();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(text) => { if socket.send(WsMessage::Text(text)).await.is_err() { break; } }
                    Err(_) => break,
                }
            }
            msg = socket.recv() => { if msg.is_none() { break; } }
        }
    }
}

async fn handle_identify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<IdentifyReq>,
) -> Response {
    #[derive(Serialize)]
    struct EnclaveIdentifyReq<'a> { fingerprint_secret: &'a str }

    match call_enclave::<_, IdentifyResp>(
        &st,
        &req.polling_unit,
        "/identify",
        &EnclaveIdentifyReq { fingerprint_secret: &req.fingerprint_secret },
    )
    .await
    {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            eprintln!("identify[{}]: {e:#}", req.polling_unit);
            err_json(StatusCode::BAD_GATEWAY, e)
        }
    }
}

async fn handle_register(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Response {
    #[derive(Serialize)]
    struct EnclaveRegisterReq<'a> { fingerprint_secret: &'a str }
    #[derive(Deserialize)]
    struct EnclaveRegisterResp { signature: String }

    match call_enclave::<_, EnclaveRegisterResp>(
        &st,
        &req.polling_unit,
        "/register",
        &EnclaveRegisterReq { fingerprint_secret: &req.fingerprint_secret },
    )
    .await
    {
        Ok(r) => Json(TxResult { signature: r.signature }).into_response(),
        Err(e) => {
            eprintln!("register/enclave[{}]: {e:#}", req.polling_unit);
            err_json(StatusCode::BAD_GATEWAY, e)
        }
    }
}

async fn handle_vote(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VoteReq>,
) -> Response {
    #[derive(Serialize)]
    struct EnclaveVoteReq<'a> { fingerprint_secret: &'a str, candidate_id: u8 }
    #[derive(Deserialize)]
    struct EnclaveVoteResp { signature: String }

    match call_enclave::<_, EnclaveVoteResp>(
        &st,
        &req.polling_unit,
        "/vote",
        &EnclaveVoteReq { fingerprint_secret: &req.fingerprint_secret, candidate_id: req.candidate_id },
    )
    .await
    {
        Ok(r) => Json(TxResult { signature: r.signature }).into_response(),
        Err(e) => {
            eprintln!("vote/enclave[{}]: {e:#}", req.polling_unit);
            err_json(StatusCode::BAD_GATEWAY, e)
        }
    }
}

// ── Tally poller ──────────────────────────────────────────────────────────────

async fn tally_poller(st: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        if let Err(e) = refresh_tally(&st).await {
            eprintln!("tally_poller: {e}");
        }
    }
}

async fn refresh_tally(st: &Arc<AppState>) -> anyhow::Result<()> {
    let candidate_count = st.candidate_names.len();
    let accounts = tokio::task::block_in_place(|| {
        st.rpc.get_program_accounts(&st.ballot_pid).context("get_program_accounts (ballot)")
    })?;

    let mut totals = vec![0u64; candidate_count];
    let mut by_state: HashMap<u8, Vec<u64>> = HashMap::new();

    for (_pubkey, account) in &accounts {
        let data = &account.data;
        if data.len() < 50 { continue; }
        if &data[0..8] != b"ballot\0\0" { continue; }
        let state_id = data[48];
        let candidate_id = data[49] as usize;
        if candidate_id >= candidate_count { continue; }
        totals[candidate_id] += 1;
        let state_counts = by_state.entry(state_id).or_insert_with(|| vec![0; candidate_count]);
        state_counts[candidate_id] += 1;
    }

    {
        let mut t = st.tally.write().await;
        t.totals = totals.clone();
        t.by_state = by_state.clone();
    }

    let snap = serde_json::json!({
        "type": "tally_update",
        "candidates": st.candidate_parties,
        "totals": totals,
        "by_state": by_state.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<HashMap<String, Vec<u64>>>(),
    });
    let _ = st.ws_tx.send(snap.to_string());
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Parse polling unit specs: id|display_name|url|hmac_key_path
    let mut enclaves: HashMap<String, PollingUnitConfig> = HashMap::new();
    let mut polling_unit_list: Vec<(String, String)> = Vec::new();
    for spec in &cli.polling_units {
        let parts: Vec<&str> = spec.splitn(4, '|').collect();
        if parts.len() != 4 {
            bail!("--polling-unit must be id|display_name|url|hmac_key_path, got: {spec}");
        }
        let id = parts[0].to_owned();
        let display_name = parts[1].to_owned();
        let url = parts[2].to_owned();
        let key_path = parts[3];
        let bytes = fs::read(key_path)
            .with_context(|| format!("read HMAC key for unit {id}: {key_path}"))?;
        if bytes.len() != 32 {
            bail!("HMAC key for unit {id} must be 32 bytes, got {}", bytes.len());
        }
        let mut hmac_key = [0u8; 32];
        hmac_key.copy_from_slice(&bytes);
        println!("polling unit: {id:10} → {url}  ({display_name})");
        polling_unit_list.push((id.clone(), display_name.clone()));
        enclaves.insert(id, PollingUnitConfig { display_name, url, hmac_key });
    }
    println!("{} polling unit(s) configured", enclaves.len());

    let candidate_names: Vec<String> = cli
        .candidate_names
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();

    let candidate_parties: Vec<String> = cli
        .candidate_parties
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();

    println!("Candidates:  {:?}", candidate_names);
    println!("Parties:     {:?}", candidate_parties);

    let ballot_pid: Pubkey = cli.ballot_program.parse()?;
    let voter_registry_pid: Pubkey = cli.voter_registry_program.parse()?;
    let (ws_tx, _) = broadcast::channel::<String>(256);

    let n = candidate_names.len();
    let state = Arc::new(AppState {
        rpc: RpcClient::new_with_commitment(cli.rpc_url.clone(), CommitmentConfig::confirmed()),
        enclaves,
        polling_unit_list,
        http: reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()?,
        ballot_pid,
        voter_registry_pid,
        election_id: cli.election_id,
        candidate_names,
        candidate_parties,
        tally: RwLock::new(TallyState::new(n)),
        ws_tx: ws_tx.clone(),
    });

    tokio::spawn(tally_poller(state.clone()));

    let app = Router::new()
        .route("/", get(handle_root))
        .route("/booth/:unit_id", get(handle_booth_unit))
        .route("/ws", get(handle_ws))
        .route("/api/tally", get(handle_tally))
        .route("/api/candidates", get(handle_candidates))
        .route("/api/polling-units", get(handle_polling_units))
        .route("/api/identify", post(handle_identify))
        .route("/api/register", post(handle_register))
        .route("/api/vote", post(handle_vote))
        .nest_service("/data", ServeDir::new(&cli.data_dir))
        .with_state(state);

    println!("dashboard-server on http://{}", cli.bind);
    axum::serve(tokio::net::TcpListener::bind(cli.bind).await?, app).await?;
    Ok(())
}
