//! dashboard-server — aggregation + WebSocket broadcast.
//!
//! Subscribes to the ballot program (via Helius webhook or RPC polling),
//! maintains in-memory (state_id, candidate_id) -> count aggregates,
//! pushes updates to connected browsers over WebSocket.
//!
//! Scaffold only — implementation lands on Days 18-20 of TIMELINE.md.

fn main() -> anyhow::Result<()> {
    println!("dashboard-server stub — see TIMELINE.md Days 18-20");
    Ok(())
}
