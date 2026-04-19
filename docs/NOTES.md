# idv2 — Running Notes & Decisions Log

Newest entries at the top. Each entry has a date and a short tag.

---

## 2026-04-18 (evening) — National HSM cluster confirmed; ZK reopened with spike gate

**HSM architecture: national cluster.** Decision confirmed. Banking POS PKI is the reference model — distributed terminals, central acquirer/scheme HSM infrastructure, DUKPT-style key management. Decades of production deployment across the card networks. For idv2:

- Logically one HSM holding all sealed voter state (sealed `identity_secret`, blinding factors `r`, biometric templates, location attributes).
- Polling booths are thin clients — biometric capture, UI, transaction relay. No sensitive state on the booth.
- Authenticated channel between booth and HSM cluster (mTLS, mutual attestation).
- For the hackathon: single SoftHSM2 instance simulates the cluster, booths connect over a local HTTP server.

This closes the "vote anywhere" gap that was implicit in yesterday's design. It also means the enclave wrapper lives with the HSM, not with the booth — a meaningful refactor of the scaffolded `enclave/` crate's conceptual role, though not of its API surface.

**ZK reopened as a tracked spike.** Research on current tooling (2026) shows the situation has shifted since yesterday's scope-out:

- **Semaphore protocol via `semaphore-rs`** (Worldcoin-maintained Rust library, uses `ark-circom` to generate Groth16 proofs) is a functional match for idv2's voting phase. The protocol is purpose-built for anonymous Merkle-tree membership + nullifier. Circuit is pre-built, audited, and consumed as a library.
- **Solana alt_bn128 precompiles** make on-chain Groth16 verification feasible within a single transaction's compute budget. ~200-byte proof size fits comfortably in transaction limits.
- **Light Protocol** provides Solana-native Merkle trees + validity proofs but is optimized for compressed-account storage, not anonymous membership. Its validity proofs reveal which leaf they prove. Not directly suitable for our use case without bending the protocol.
- **SP1 / risc0** zkVMs are a third option (write Rust, get a SNARK) but proof generation latency is high and Solana verifier integration is less mature for our specific needs.

**Decision: two-day spike in Phase 1 with hard go/no-go gate at end of Day 3.**

- Day 2 spike: build `semaphore-rs` locally, generate a test Groth16 proof over a toy Merkle tree. Pure Rust, no Solana.
- Day 3 spike: adapt an existing open-source Solana Groth16 verifier reference to verify the Semaphore proof on devnet.
- **Pass criteria:** both spikes produce working output by end of Day 3. If yes → ZK is back in scope and we update TIMELINE.md to integrate Semaphore into registration and voting. If no → fall back to the non-ZK demo path.

This bounds the risk. Worst case: one lost Phase 1 day. Best case: actual anonymous voting, not demo-only anonymity.

---

## 2026-04-18 (later still) — `Tally` program is now a stretch goal

Not a hard problem to build, just time-consuming (another Pinocchio program to write, test, and deploy). Moving it out of core scope:

- **If Phase 5 buffer days are available (Day 22+ running ahead of schedule):** build the on-chain `Tally` program. Adds a canonical, permanent record of the final tally stored on-chain.
- **If not:** cut it. The aggregation CLI + on-chain BallotAccounts already give us the "anyone can verify" property. No security or audit story is lost by omission.

Decision deferred to end of Phase 4 (Day 21). Do not start the Tally program before then.

---

## 2026-04-18 (later) — Cryptographic clarifications & scope adjustments

Three decisions locked after a deep-dive Q&A on the primitives.

**Decision 1: Keep Pedersen commitments on Ristretto255 (do not drop to hash commitments).**

The demo path does not technically need Pedersen — a hash commitment `H(NIN || biometric || salt || state_id || lga_id)` would work fine for Merkle membership, since we are not doing ZK and not doing homomorphic tally. However, Pedersen preserves the ZK upgrade path cleanly (Groth16/PLONK circuits work natively with algebraic commitments; hash commitments would force a tree rebuild later). Cost is ~20 extra lines via `curve25519-dalek`. Net: keep Pedersen. "We committed the upgrade path into the design from day one" is a stronger narrative than "we would rebuild later."

**Decision 2: WOTS lifecycle spans registry AND ballot — they are one mechanism, not two.**

Making this explicit so it is not re-litigated. At registration: HSM generates WOTS keypair, public key is bound into the identity commitment, secret is sealed inside the HSM and never leaves. At ballot cast: HSM uses the sealed secret to sign the vote message; the signature + public key + Merkle proof go on-chain. The monotonic counter gates the signing operation and tracks WOTS leaf usage to prevent key reuse. The HSM boundary, the WOTS primitive, and the counter are a single system — if any one is broken the whole thing collapses.

Tree depth 1 is the default (one key per voter per election, destroyed after signing). Multi-election support later would use a WOTS+ Merkle tree of OTS keys with the counter tracking the next unused leaf.

**Decision 3: Scope down the tally verifier CLI to aggregation-only.**

Original spec had the CLI re-verifying every signature and every Merkle proof. This is redundant with Solana consensus, which already verified those at submission time. Scoping the CLI down to: fetch all BallotAccounts → deserialize → aggregate per candidate and per state → print deterministic JSON report. ~100 lines instead of ~300. The independent-reproducibility story still holds — anyone with an RPC endpoint can regenerate the same numbers — and the cryptographic verification path is documented in the README as "Solana consensus is the verification layer; the CLI is the aggregation layer."

**Decision 4: Dashboard and CLI are side-by-side independent consumers.**

Confirmed the architecture: dashboard (aggregation server + map + WebSocket) is the live presentation layer; CLI is the on-demand audit layer. No shared runtime dependency beyond the underlying Solana accounts. Dashboard going down does not compromise audit; CLI having a bug does not affect the dashboard. Both land in the final deliverable.

---

## Open questions (updated)

- [ ] Anchor the 26-day timeline to a calendar start date.
- [ ] Confirm submission format (demo video vs. live demo) — affects Day 24–25 plan.
- [ ] Validate WOTS+ Rust crate availability on Day 3; fallback decided if unusable.
- [ ] Decide on WOTS tree depth — default 1 for the demo; confirm we are not planning multi-election demo scenarios.

---

## 2026-04-18 — Project folder created

- Spun up a dedicated idv2 folder so the project has a persistent home across Cowork sessions.
- Regenerated the v0.1 report, project plan, and revised 26-day timeline from yesterday's discussion transcript.
- **Decision:** attestor removed from the trust model at all phases (including registration). Confirmed against the NIMC compromise threat model. Fusion architecture rejected.
- **Decision:** ZK circuit scoped out of the hackathon submission. Solo-dev constraint makes a correct implementation unrealistic in 26 days. Demo path uses Ed25519 over the nullifier + direct Merkle proof verification. Documented as the production upgrade path.
- **Decision:** software monotonic counter is sufficient for the hackathon. Hardware NV counter documented as production concern.

---

## Architectural principles (do not violate without updating this file)

- No NIN, wallet address, or biometric template ever touches Solana.
- No trusted attestor at any phase.
- Pinocchio everywhere. No Anchor unless a future ZK verifier forces it.
- Every secret lives inside the enclave boundary.
- Every on-chain write must be independently verifiable by the tally CLI.

---

## Template for future entries

```
## YYYY-MM-DD — <short title>

- What changed.
- Why.
- What was considered and rejected.
- Any follow-up items.
```
