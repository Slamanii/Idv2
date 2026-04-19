# idv2 — 26-Day Timeline (ZK scoped out)

**Version:** v0.1 (revised post-scope-cut)
**Date:** 2026-04-18

Written in Day-N terms. Anchor to a real start date in `NOTES.md` once confirmed.

---

## Phase 1 — Foundation (Days 1–3)

**Day 1.** Rust workspace scaffold. Cargo workspace compiles with empty `lib.rs` files. Solana CLI + Pinocchio tooling installed. Localnet runs. SoftHSM2 installed and accessible via `pkcs11-tool`. **Exit: M1.**

**Day 2.** Two tracks running in parallel (both small enough to fit in a day):
  - Track A: `cryptoki` crate integration test — open token, create object, seal a byte string, read it back. Validate on the target macOS environment. If blocked, execute the file-sealed fallback documented in `PROJECT-PLAN.md` risks.
  - Track B (ZK spike #1): Build `semaphore-rs` locally, generate a test Groth16 proof over a toy 4-leaf Merkle tree, verify it locally. Pure Rust, no Solana involvement. Budget: 3–6 hours. If `semaphore-rs` won't build or the toy proof doesn't verify, flag the ZK path as unlikely before Day 3 even starts.

**Day 3.** Two tracks again:
  - Track A: WOTS+ library validation. Run `pqcrypto-wots` (or chosen alternative) through key generation and a single signature/verification round. If library is not usable, commit to Ed25519-everywhere for the demo path and document.
  - Track B (ZK spike #2): Adapt an open-source Solana Groth16 verifier reference to verify the Day 2 Semaphore proof on devnet. Budget: 4–8 hours.
  - **End-of-day go/no-go gate on ZK:** if both spikes pass, ZK is back in scope — update subsequent phases to integrate Semaphore into registration and voting, and bump REPORT to v0.2 reflecting the integration. If either spike fails or looks >1 day from working, fall back to the non-ZK demo path and continue with the current timeline unchanged.

---

## Phase 2 — Enclave & Registration (Days 4–8)

**Day 4.** Enclave wrapper API surface implemented. `register()`, `authenticate()`, `sign_vote()`, `destroy_session()` compile with mock internals.

**Day 5.** Monotonic counter implemented. Atomic file write via write-temp-fsync-rename. Unit tests for crash recovery (kill -9 mid-write should leave counter consistent).

**Day 6.** `register()` filled in — Pedersen commitment over `H(NIN || biometric || salt || state_id || lga_id)` on Ristretto255, `identity_secret` sealed inside the PKCS#11 token.

**Day 7.** Sparse Merkle Tree server. In-memory tree with 2^20 capacity for the demo. Unit tests against an independent reference implementation.

**Day 8.** `election_registry` and `voter_registry` Pinocchio programs. Localnet test: submit a commitment, observe the root update, serve a membership proof.
**Exit: M2 and M3.**

---

## Phase 3 — Voting Core (Days 9–15)

**Day 9.** `ballot` Pinocchio program skeleton — account layouts, instruction handlers, no verification yet. Deploys to localnet.

**Day 10.** Merkle proof verification inside `ballot`. Reject votes whose proof does not validate against the current `VoterRegistryAccount` root.

**Day 11.** Nullifier PDA — derivation, collision check, atomic marking. Double-vote rejection test passes.

**Day 12.** Signature verification inside `ballot`. Ed25519 path wired; WOTS path wired if Day 3 succeeded.

**Day 13.** `sign_vote()` in the enclave — composes the full vote transaction, submits via client.

**Day 14.** First end-to-end vote. Register a single voter via the enclave, submit a vote, observe a `BallotAccount` land on localnet. **Exit: M4.**

**Day 15.** Buffer day. Fix whatever broke in Day 14. Do not skip this — it always breaks.

---

## Phase 4 — Booth UI & Dashboard (Days 16–21)

**Day 16.** Booth UI skeleton. Three HTML screens (thumbprint / select / confirm). Mock fingerprint with a button press. Wires to the enclave via a thin local HTTP server.

**Day 17.** Booth UI polish — error states, transaction pending indicator, confirmation screen with transaction signature. Full flow works end-to-end on a single laptop.

**Day 18.** Aggregation server — Helius webhook (or direct RPC polling fallback) → in-memory aggregation → WebSocket broadcast.

**Day 19.** Dashboard HTML + Leaflet.js + Nigeria GeoJSON. Map renders. Candidate colour legend. Table below with sort and filter.

**Day 20.** Live update wire-up. Vote at the booth UI → Solana → aggregation → dashboard recolours within 2 seconds. **Exit: M5.**

**Day 21.** Tally verifier CLI (aggregation-only — scope-cut 2026-04-18). Fetches all BallotAccounts, deserializes, aggregates per candidate and per state, outputs deterministic JSON report. No signature or Merkle proof re-verification — Solana consensus already did that at submission time. Run against the localnet test dataset and confirm the JSON matches the dashboard totals.

---

## Phase 5 — Integration & Polish (Days 22–26)

**Day 22.** End-to-end test harness — 100 simulated voters, 3 candidates, full lifecycle. All five security properties asserted programmatically. **Exit: M6.**

**Day 23.** Devnet deployment. All four Pinocchio programs live on Solana devnet. Dashboard pointed at devnet. Run the test harness against devnet.

**Day 24.** README, architecture diagram (draw.io or Mermaid), production-upgrade-path section. Demo script walk-through written out.

**Day 25.** Demo video recording or dress rehearsal for live demo — whichever the submission format requires. Edit for clarity.

**Day 26.** Submission. Buffer for last-minute fixes. Do not write new code on Day 26.

---

## Hard gates

- **End of Day 15:** Layer 1 + first vote must work. If not, scope-cut Layer 3 polish.
- **End of Day 20:** Dashboard live. If not, ship a static results page.
- **Day 26:** No new code.

## What I will not do

- No ZK circuit. Documented as future work in the README.
- No Anchor programs.
- No real biometric hardware.
- No real NIMC integration — interface is mocked and the integration contract documented.
