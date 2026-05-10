//! SMT server — off-chain incremental Merkle tree + proof service.
//!
//! Mirrors the voter_registry on-chain commitment tree.  The relayer calls
//! `/insert` after each successful `insert_commitment` Solana tx; voters
//! call `/proof` to get the Merkle path needed for `ballot::cast`.
//!
//! ## Endpoints
//!
//!   POST /insert  { "commitment": "<64-hex>" }
//!     → { "index": N, "root": "<64-hex>" }
//!
//!   POST /proof   { "commitment": "<64-hex>" }
//!     → { "index": N, "path": ["<64-hex>"; 28], "path_indices": N, "root": "<64-hex>" }
//!     → 404 if commitment not in tree
//!
//!   GET  /root
//!     → { "root": "<64-hex>", "leaf_count": N }
//!
//! ## Running locally
//!
//!   cargo run -p smt-server              # default port 8765
//!   cargo run -p smt-server -- --port 9000
//!   PORT=9000 cargo run -p smt-server    # env var override
//!
//! ## CORS
//!
//!   The server attaches permissive CORS headers (`Access-Control-Allow-Origin: *`)
//!   so the dashboard (running on a different localhost port) can call /proof and
//!   /root from the browser.  CLI tools (curl, relayer) are unaffected.
//!   Tighten to a specific origin before any internet-facing deployment.

mod tree;

use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tree::IncrementalMerkleTree;

// ── CLI args ──────────────────────────────────────────────────────────────────

fn resolve_port() -> u16 {
    // Priority: --port flag > PORT env var > default 8765
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--port") {
        if let Some(val) = args.get(pos + 1) {
            if let Ok(p) = val.parse::<u16>() {
                return p;
            }
        }
    }
    std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8765)
}

// ── Shared state ──────────────────────────────────────────────────────────────

type AppState = Arc<Mutex<IncrementalMerkleTree>>;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct CommitmentReq {
    /// Raw 32-byte Pedersen commitment, hex-encoded (64 hex chars).
    commitment: String,
}

#[derive(Serialize)]
struct InsertResp {
    index: u64,
    root: String,
}

#[derive(Serialize)]
struct RootResp {
    root: String,
    leaf_count: u64,
}

#[derive(Serialize)]
struct ProofResp {
    index: u64,
    /// 28 sibling hashes from leaf level to root level, hex-encoded.
    path: Vec<String>,
    /// Bit i == 0 → leaf is the left child at level i.  Equals the leaf index.
    path_indices: u32,
    root: String,
}

// ── Hex helpers ───────────────────────────────────────────────────────────────

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let bytes: Result<Vec<u8>, _> = (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
        .collect();
    bytes
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "slice length mismatch".to_string())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn insert_handler(
    State(state): State<AppState>,
    Json(body): Json<CommitmentReq>,
) -> impl IntoResponse {
    let commitment = match from_hex_32(&body.commitment) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response()
        }
    };
    let mut tree = state.lock().unwrap();
    let index = tree.insert(&commitment);
    let root  = to_hex(&tree.root());
    (StatusCode::OK, Json(InsertResp { index, root })).into_response()
}

async fn proof_handler(
    State(state): State<AppState>,
    Json(body): Json<CommitmentReq>,
) -> impl IntoResponse {
    let commitment = match from_hex_32(&body.commitment) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response()
        }
    };
    let tree = state.lock().unwrap();
    match tree.proof(&commitment) {
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "commitment not in tree" })),
        )
            .into_response(),
        Some(p) => {
            let path: Vec<String> = p.path.iter().map(|s| to_hex(s)).collect();
            (
                StatusCode::OK,
                Json(ProofResp {
                    index: p.index,
                    path,
                    path_indices: p.path_indices,
                    root: to_hex(&p.root),
                }),
            )
                .into_response()
        }
    }
}

async fn root_handler(State(state): State<AppState>) -> Json<RootResp> {
    let tree = state.lock().unwrap();
    Json(RootResp {
        root: to_hex(&tree.root()),
        leaf_count: tree.leaf_count(),
    })
}

/// Returns the Merkle siblings needed to insert the NEXT leaf.
///
/// The relayer calls this before every `insert_commitment` instruction.
/// `path_indices` equals the current leaf count — pass it directly as
/// `path_indices` in the instruction data.
async fn insert_path_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let tree = state.lock().unwrap();
    let p = tree.insertion_path();
    let path: Vec<String> = p.path.iter().map(|s| to_hex(s)).collect();
    Json(serde_json::json!({
        "index":        p.index,
        "path":         path,
        "path_indices": p.path_indices,
        "root":         to_hex(&p.root),
    }))
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port = resolve_port();

    let state: AppState = Arc::new(Mutex::new(IncrementalMerkleTree::new()));

    // CORS: allow any origin so the dashboard (different localhost port) can
    // call /proof and /root from the browser.  CLI tools are unaffected.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/insert",      post(insert_handler))
        .route("/proof",       post(proof_handler))
        .route("/root",        get(root_handler))
        .route("/insert-path", get(insert_path_handler))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    println!("smt-server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
