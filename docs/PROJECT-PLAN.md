# idv2 — Project Plan

**Version:** v0.1
**Date:** 2026-04-18
**Status:** Ready to execute

---

## What we are building

A solo-developer hackathon implementation of idv2 — an anonymous, cryptographically verifiable voting system for Nigerian general elections. Built in four layers.

---

## Layer 1 — Identity & Registration

**Objective.** Verify a real voter exists, seal their secret inside hardware, add only a commitment to the registry.

**Deliverables:**

- Identity Verification Service — accepts NIN + live biometric, requests government commitment for the NIN, confirms match locally. Mocked for the hackathon with a deterministic stub that accepts any well-formed NIN.
- Secure Enclave wrapper (SoftHSM2 + PKCS#11 via Rust `cryptoki`) — generates `identity_secret`, computes `identity_commitment`, stores `(identity_secret, state_id, lga_id)` internally, returns commitment only.
- Software monotonic counter — atomically written file, prevents WOTS key reuse.
- Sparse Merkle Tree server (Rust) — accepts commitments, maintains tree, publishes root to Solana, serves membership proofs.
- `ElectionAccount` and `VoterRegistryAccount` programs (Pinocchio) — store Merkle root on-chain.

**Definition of done.** A CLI can submit 100 synthetic registrations and the resulting Merkle root matches an independent recomputation.

---

## Layer 2 — Voting

**Objective.** Voter arrives at any booth, authenticates biometrically, casts an anonymous vote, it lands on-chain in under a second.

**Deliverables:**

- Booth voting UI (plain HTML, three screens: thumbprint → candidate select → confirm).
- Enclave voting handler — biometric unlock → load `identity_secret` → compute nullifier → retrieve Merkle proof → sign with WOTS (or Ed25519 in demo) → broadcast transaction.
- `Ballot` program (Pinocchio) — verifies signature, Merkle proof, nullifier uniqueness, writes `BallotAccount` with `{candidate_id, state_id, lga_id, nullifier, slot}`.
- `NullifierAccount` PDA — atomic double-vote prevention.

**Definition of done.** A voter can authenticate at the booth UI, select a candidate, and observe a `BallotAccount` landing on Solana devnet within 1 second. A second attempt with the same voter is rejected with a clear error.

---

## Layer 3 — Results & Auditability

**Objective.** Anyone can watch votes land in real time, see results by state, verify the tally independently.

**Deliverables:**

- Aggregation server (Rust) — Helius webhook subscription to the voting program, maintains in-memory `(state_id, candidate_id) → count` map, pushes updates to the dashboard over WebSocket.
- Results dashboard (HTML + Leaflet.js) — choropleth map of Nigeria's 36 states + FCT coloured by leading candidate, live-updating filterable table below.
- Tally verifier binary (Rust CLI) — permissionless, fetches all BallotAccounts, deserializes, aggregates per candidate and per state, outputs deterministic JSON audit report. *Scoped down 2026-04-18:* does not re-verify signatures or Merkle proofs (Solana consensus already did that at submission time). The CLI is an aggregation + reproducibility tool, not a cryptographic verification layer. Independent audit story: anyone with a Solana RPC endpoint and the election ID regenerates the same numbers byte-for-byte.
- `Tally` program (Pinocchio) — *STRETCH GOAL as of 2026-04-18.* Stores the final canonical tally on-chain once the election closes. Built only if Phase 5 buffer days are available (decision checkpoint at end of Day 21). No security story is lost if cut.

**Relationship between the dashboard and the CLI.** They are independent side-by-side consumers of the same public on-chain data. Dashboard is the live presentation layer for voters and observers watching in real time. CLI is the on-demand audit layer for journalists, observers, and anyone needing a reproducible artifact. No shared runtime dependency — if the dashboard server goes offline mid-election, the CLI still works; if the CLI has a bug, the dashboard is unaffected. Both read BallotAccounts directly from Solana.

**Definition of done.** Live votes landing on Solana devnet show up on the map within 2 seconds. The tally verifier CLI produces a report that matches the dashboard aggregates exactly.

---

## Layer 4 — Glue & Infrastructure

**Objective.** Ship a cohesive, demonstrable system.

**Deliverables:**

- Solana Devnet deployment of all four Pinocchio programs.
- Rust workspace structure: `programs/`, `clients/`, `enclave/`, `dashboard/`, `tests/`.
- End-to-end test harness — 100 simulated voters, 3 candidates, full lifecycle on localnet, asserting all five security properties.
- Nigeria GeoJSON (public, drop-in).
- README with architecture diagram, setup instructions, and the production-upgrade path (ZK circuit, hardware HSM, real NIMC integration).

---

## Milestones

| # | Milestone | Definition of Done |
|---|-----------|---------------------|
| M1 | Rust workspace compiles | All four crates build on `cargo build --workspace` with empty `lib.rs` files. |
| M2 | Enclave registers a voter | `register()` returns a commitment; `identity_secret` is sealed inside SoftHSM2; monotonic counter initialised. |
| M3 | First voter commitment on Solana | A single commitment reaches `VoterRegistryAccount`; Merkle root updates; localnet test passes. |
| M4 | First ballot on Solana | A `BallotAccount` is written; signature verifies; nullifier marks the slot used. |
| M5 | Dashboard renders live votes | Map recolours within 2 seconds of a vote landing. |
| M6 | Full E2E passes | 100 voters / 3 candidates complete the lifecycle on localnet with zero manual intervention. |

---

## Pinocchio vs. Anchor — decision matrix

| Component | Framework | Rationale |
|-----------|-----------|-----------|
| `election_registry` | Pinocchio | Simple state, zero-copy beneficial, no Anchor overhead needed. |
| `voter_registry` | Pinocchio | Merkle root updates are cheap; account layout is trivial. |
| `ballot` | Pinocchio | Hot path — every vote hits this program. Minimising CU budget matters. |
| `tally` | Pinocchio | Read-heavy, simple writes at election close. |
| ZK verifier (future) | Anchor | If we re-scope in ZK, the Anchor ecosystem has better Groth16 verifier libraries. |

---

## Key Rust dependencies

| Crate | Purpose |
|-------|---------|
| `pinocchio` (latest) | Pinocchio runtime for all four programs |
| `cryptoki` = "0.8" | PKCS#11 bindings for SoftHSM2 |
| `curve25519-dalek` = "4" | Ristretto255 Pedersen commitments |
| `sha2` = "0.10" | Commitment + nullifier hashing |
| `ed25519-dalek` = "2" | Demo-path signing |
| `solana-client` | RPC client for aggregation + verifier |
| `serde`, `serde_json` | Standard serialization |
| `tokio` | Aggregation server runtime |
| `axum` | WebSocket server for dashboard |
| `pqcrypto-wots` (investigate) | WOTS+ signatures — validate API before committing |

---

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| WOTS+ Rust library not production-ready | High | Fall back to a hand-rolled WOTS+ implementation (~200 LOC from spec) or use Ed25519 throughout the demo path with WOTS documented as production. |
| SoftHSM2 + `cryptoki` integration has quirks on macOS | Medium | Test on day 2; if blocked, use `rustls-pkcs11` or a plain file-sealed implementation as a fallback with the PKCS#11 API surface preserved. |
| Helius free tier insufficient for demo load | Low | Fall back to direct RPC polling at 1 Hz; demo load is trivial (≤100 votes). |
| Nigeria GeoJSON boundaries are stale | Low | Accept; boundary accuracy is not a judge-visible concern. |
| Scope creep from attempting ZK late | Medium | Hard gate: if Layer 1 + Layer 2 are not complete by Day 20, no ZK work begins. |
