# idv2 — Project Context

**Owner:** Adrian
**Status:** Pre-build, architecture locked
**Last updated:** 2026-04-18

> This file is the single source of truth for anyone (me, or a fresh Cowork session) opening this folder. Read this first.

---

## What idv2 is

An Iterative/Interoperable Decentralized Voting system (v2) targeting Nigerian general elections. Voters register once at a geopoint-verified location, then can vote from any polling booth in the country. Votes land on Solana in real time. No voter's identity is linkable to their vote after registration closes.

This is being built as a **solo hackathon submission** (software track).

---

## The design journey (short version)

1. **Option A** — trusted attestor (NIMC-style) signs eligibility attestations; smart contract mints SBT; vote is wallet-bound. Pragmatic but pseudonymous. Attestor compromise = full system compromise.

2. **Pivot to IDv2** — the attestor was judged too risky in the Nigerian context (documented NIMC data incidents, realistic coercion vectors). Moved to a full cryptographic privacy stack: Merkle commitments, nullifiers, enclave-sealed secrets, anonymous vote proofs.

3. **Claude's fusion recommendation (rejected)** — use Option A's attestor *only* at registration to insert commitments into the IDv2 tree, then go fully anonymous. Attestor out of the picture post-registration.

4. **Final decision** — Adrian rejected the fusion on the grounds that a compromised attestor can insert ghost voters even at registration time, which is undetectable. **The attestor is removed from the trust model entirely, including at registration.** A stronger biometric verification layer replaces what the attestor was doing.

---

## Architectural pillars (locked)

- **Pinocchio programs on Solana** — no Anchor unless ZK complexity forces it
- **Secure Enclave holds all voter secrets** — SoftHSM2 + PKCS#11 via Rust `cryptoki` crate for the hackathon; hardware HSM/TPM in production
- **WOTS signatures** inside the enclave — protected by a software monotonic counter (60–80 lines of Rust, atomic file write + fsync + rename)
- **Merkle commitment tree** — voter identity never on-chain, only `H(NIN || biometric || salt || state_id || lga_id)` commitments
- **Nullifier scheme** — `H(identity_secret || election_id)` prevents double-voting anonymously
- **Location committed at registration** — `state_id: u8`, `lga_id: u16` stored plain in BallotAccount (public geography, no privacy loss); committed to inside the identity commitment so validators can verify consistency
- **Vote anywhere, counted by registration location** — enclave lives in the polling booth, carries location from registration record into the signed vote message
- **Real-time Solana writes** — Helius webhook → aggregation server → WebSocket → live Leaflet.js choropleth map of 36 states + FCT

---

## Scope decisions for the hackathon (solo-dev constraint)

**In scope:**
- Four Pinocchio programs: `election_registry`, `voter_registry`, `ballot`, `tally`
- SoftHSM2 enclave wrapper with software monotonic counter
- WOTS signing + Merkle membership verification (direct, on-chain)
- Nullifier-based double-vote prevention
- Three-screen booth UI (thumbprint → candidate select → confirm)
- Live dashboard with Nigeria choropleth map + filterable results table
- End-to-end test harness with 100 simulated voters / 3 candidates on localnet

**Out of scope (documented as production upgrade path):**
- **ZK circuit (Groth16/PLONK)** — too much work for a solo dev in 26 days. Replaced for the demo by Ed25519 signing of the nullifier + direct Merkle proof verification. The architecture document explicitly shows where the ZK circuit would slot in.
- **Hardware-backed NV monotonic counter** — software counter is sufficient for the hackathon; judges understand the hardware layer is a production concern.
- **Real biometric hardware** — the demo uses a button press to simulate fingerprint capture; the enclave wrapper accepts the same API surface either way.

---

## Open questions (to resolve in the next session)

- **Calendar anchoring.** The 26-day timeline is written in `Day 1 … Day 26` terms. Confirm a start date so milestones map to dates.
- **ZK circuit stretch goal.** If Layer 1 + Layer 2 ship ahead of schedule, is writing a minimal Groth16 membership circuit worth attempting in the last 3 days? (Low priority — only if everything else is clean.)
- **Demo video vs. live demo.** Submission format affects what "done" looks like for the dashboard polish phase.

---

## How to use this folder

- `docs/REPORT-v0.1.md` — the full design narrative in first person (Option A → IDv2 → rejection of fusion). Edit as the design evolves; bump version in the filename.
- `docs/PROJECT-PLAN.md` — the 4-layer build plan, account layouts, milestones, risks.
- `docs/TIMELINE.md` — revised 26-day timeline with ZK scoped out.
- `docs/NOTES.md` — running log of decisions, questions, and changes. Add a dated entry at the top of this file whenever something material changes.
- `rust-workspace/` — scaffolded Cargo workspace. Empty `lib.rs` files in each crate; fill in as each layer is built.
