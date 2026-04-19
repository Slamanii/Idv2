# idv2 — Design Report

**Version:** v0.1
**Author:** Adrian
**Date:** 2026-04-18
**Status:** Living document — will be edited as the build progresses.

---

## Part I — The Design Narrative (Pragmatic)

### Where I started: Option A

I started from a pragmatic place. I wanted a voting system grounded in Nigerian realities — NIMC owns the national identity database, the NIN is the natural anchor, and the existing infrastructure is attestor-shaped. So I drew up what I call **Option A**: a trusted attestor, off-chain, checks the NIN, bundles a voter's attributes (state, age) into a signed attestation, and the user submits it on-chain. The smart contract verifies the signature, mints a soulbound token (or flips an eligibility bit), and the wallet can now vote. Short-lived attestations handle key rotation per election.

Option A was attractive because it maps cleanly onto what already exists. NIMC signs, the chain trusts NIMC, votes are recorded. Done.

### Why I walked away from it

The deeper I looked at Option A, the harder it became to defend the trust assumption at its core. The entire system collapses to: *can NIMC's signing key ever be misused?* In Nigeria specifically, that question has a worrying answer. There have been documented NIMC data incidents. State actors, political operatives, and contractors with write access are all realistic threat vectors. An attestor that signs a fake attestation for a ghost voter produces a perfectly valid eligibility record — and nothing on-chain can detect the lie. Worse, the attestor always knows which NIN maps to which wallet. That mapping is a single subpoena away from destroying voter privacy, which kills any real claim to coercion-resistance.

So Option A is pseudonymity, not anonymity. In a system where voter coercion and vote-buying are non-trivial concerns, that is not good enough.

### Why I moved to IDv2

I pivoted to a full cryptographic stack and called it IDv2. The core shift is that **identity never appears on-chain in any form** — not even hashed. What goes on-chain is a Merkle root of voter commitments. Each commitment is `H(NIN || biometric || salt || state_id || lga_id)`. When I vote, I generate a proof that says "I know a secret whose commitment is in this tree" without revealing *which* commitment, plus a nullifier `H(identity_secret || election_id)` that marks my slot as used without anyone learning it was mine.

The signing primitive inside the secure enclave is WOTS. The biometric only ever unlocks the enclave — it is never transmitted or stored outside the hardware boundary. The enclave stores `(identity_secret, state_id, lga_id)` at registration time. When I turn up at any polling booth on election day, the enclave loads those values, constructs the vote payload, signs it, and the vote lands on-chain. I am authenticated by my body. My identity is never revealed.

### Consulting Claude and the fusion recommendation

I brought this to Claude and got a useful pushback. Claude flagged the WOTS one-time property as a genuine concern — if the enclave ever signs two messages with the same WOTS key, the private key is algebraically recoverable. In production HSMs this has happened. The fix is a monotonic counter. In hardware that's non-volatile memory the CPU cannot decrement. In software it's a file, atomically written, read before every signing operation. Claude argued the software version is adequate for a hackathon because a rollback attack requires host root access, and at that level of compromise the system is already broken regardless of the counter.

Claude then recommended a **fusion architecture**: use Option A's attestor *only* at registration, specifically to add the voter commitment into the IDv2 tree. The attestor signs off that the NIN is real, the commitment goes in the tree, the attestor discards the mapping. From that point on, voting runs fully on IDv2 — ZK proof, nullifier, on-chain verification. The attestor can prove every leaf was eligible, but cannot prove which leaf voted.

### Why I rejected the fusion

The fusion is elegant but it does not survive the Nigerian threat model. A compromised attestor — even one restricted to the registration phase — can silently insert ghost voter commitments whose `identity_secret` it knows. It can then vote on behalf of those ghosts later, indistinguishably from real voters, and nothing downstream can detect it. The commitments look identical. The proofs verify. The nullifiers look fresh.

Removing the attestor entirely, including at registration, is the right architectural call. The replacement is a stronger biometric verification layer: the user enters a NIN, the system requests a government hash or commitment for that NIN (not a full identity lookup), the user provides a live biometric, the system computes a local hash and compares against the government commitment — ideally through a zero-knowledge proof or a direct match. No attestor signature. No trusted intermediary.

The tradeoff is real: this requires that NIMC exposes a commitment API, which is a political and engineering problem beyond the scope of the hackathon. For the demo I will mock this interface and document the integration contract clearly.

### The final architecture

What I am building is IDv2 as originally conceived, with no attestor in the trust model at any phase. Registration runs through a secure enclave that computes the commitment locally and adds it to a Merkle tree whose root is published on Solana. Voting runs through the same enclave at any polling booth, producing a Merkle membership proof, a nullifier, and a WOTS signature over a vote payload containing the voter's registered location. Results land on Solana in near-real time and a live dashboard colours a map of Nigeria's 36 states by the leading candidate.

For the hackathon specifically, I have scoped out the ZK circuit. I had a candid conversation with Claude about whether a solo dev can write a Groth16 Merkle membership circuit in 26 days while also building four Pinocchio programs, the enclave wrapper, the booth UI, and the dashboard. The honest answer is no. A half-working ZK circuit is worse than no ZK circuit. The demo will use direct Merkle proof verification and Ed25519 signatures over the nullifier. The architecture document describes the ZK circuit as the production upgrade path, with a clear spec for what it would prove. Judges who understand ZK will respect the honesty; judges who don't will see a complete system that does exactly what it claims.

---

## Part II — The Engineering Detail

### Security properties

The system is required to hold five properties:

**Eligibility.** Only voters whose commitment is in the on-chain Merkle root can produce a verifiable vote. This is enforced by the Merkle proof check inside the ballot program.

**Secrecy.** No observer — including validators, the government, the enclave vendor, or the dashboard operator — can link a vote to a voter. This is enforced by the commitment scheme (no NIN or wallet address ever on-chain) and the nullifier scheme (no reuse is detectable without linking identity).

**One-person-one-vote.** Each voter can vote at most once per election. This is enforced by the nullifier, which is a deterministic function of `(identity_secret, election_id)`. The ballot program stores a NullifierAccount PDA at `H(nullifier)` and rejects any second vote carrying the same nullifier.

**Integrity.** No vote can be altered, dropped, or forged after submission. This is enforced by Solana's consensus and by the WOTS signature over the vote payload; a forged vote would require either breaking the signature or compromising the enclave.

**Verifiability.** Any observer can independently recompute the tally. This is enforced by making all BallotAccounts public and providing a permissionless tally verifier binary that fetches all ballots, checks every signature and proof, and outputs the totals.

### Cryptographic primitives

**Pedersen commitments on Ristretto255** for the voter identity commitments. The commitment equation is `C = r·H + m·G`, where `G` and `H` are two Ristretto255 generators with unknown discrete log relation, `m` is the message (the identity tuple), `r` is a per-voter random blinding factor, and `C` is the resulting 32-byte Ristretto point stored as a leaf in the Merkle tree. **Hiding is perfect** (information-theoretic — for any C, every possible message is equally likely given a uniformly random r). **Binding is computational** under the discrete log assumption on Ristretto255 (opening C to two different messages would require knowing log_G(H), which is unknowable by construction since H is derived from a hash). Ristretto255 is chosen over raw Curve25519 because it eliminates cofactor-related subgroup attacks and encoding malleability.

Note on necessity: the demo path does not strictly require Pedersen — a hash commitment would be sufficient for Merkle membership, since the demo does not use ZK proofs or homomorphic tally. Pedersen is retained because it preserves a clean upgrade path to Groth16/PLONK ZK proofs without requiring the Merkle tree to be rebuilt under a different commitment scheme.

**WOTS+ signatures** for vote signing inside the enclave. WOTS is used for its post-quantum security — a production voting system must survive the 10-year horizon during which quantum computers may become cryptographically relevant. The WOTS lifecycle spans *both* registration and ballot cast and is one system, not two: at registration the HSM generates the keypair and binds the public key into the voter's identity commitment; the secret never leaves the HSM. At ballot cast the HSM uses the sealed secret to sign the vote message. The signature, public key, and Merkle proof all go on-chain where the ballot program verifies them.

WOTS is a genuine one-time signature scheme — signing two messages with the same WOTS key leaks enough of the secret that an attacker can forge a third signature. For single-election use, tree depth 1 is the default (one key = one vote = key destroyed after signing). The monotonic counter inside the HSM gates each signing operation and prevents key reuse. Multi-election support would use a WOTS+ Merkle tree of OTS keys with the counter tracking the next unused leaf.

In the demo, the nullifier alone is signed with Ed25519 because the WOTS+ overhead on the demo signing path is not interesting to judges and the Pinocchio program verification cost is non-trivial.

**Merkle trees** for voter registry membership. Sparse Merkle tree with 2^32 capacity, SHA-256 internal hashing. The root is stored in a single 32-byte field on the `ElectionAccount`.

**Nullifiers** as `SHA-256(identity_secret || election_id)`. Deterministic, collision-resistant, and unlinkable to the identity without knowledge of the secret.

### Threat model

**In scope:**
- Host OS compromise after registration (mitigated by enclave sealing of `identity_secret`)
- Solana validator collusion (mitigated by cryptographic verification; validators cannot forge Merkle proofs)
- Dashboard operator compromise (cannot affect tally, only presentation)
- Passive network observation (mitigated by on-chain-only state and TLS to RPC)

**Partially in scope:**
- Enclave rollback attacks (mitigated by the software monotonic counter; requires root access + FS manipulation to defeat)
- Biometric replay (mitigated by liveness checking in the enclave, currently mocked)

**Out of scope:**
- Physical destruction of booth hardware (operational problem, not cryptographic)
- Social engineering of voters at the booth (operational problem)
- Quantum attacks on Ristretto255 or Ed25519 (mitigated in the post-quantum upgrade path via WOTS+ and SPHINCS+ for commitment signatures)

### On-chain account layouts (Pinocchio, zero-copy, no discriminators)

```
ElectionAccount (PDA)
  election_id:           [u8; 32]
  start_slot:            u64
  end_slot:              u64
  voter_merkle_root:     [u8; 32]
  candidate_count:       u8
  _padding:              [u8; 7]
  Total:                 88 bytes

BallotAccount (PDA, one per vote)
  nullifier:             [u8; 32]
  candidate_id:          u8
  state_id:              u8
  lga_id:                u16
  slot_submitted:        u64
  signature:             [u8; 64]
  Total:                 112 bytes

NullifierAccount (PDA at H(nullifier))
  marked:                u8
  Total:                 1 byte

VoterRegistryAccount (PDA, one per election)
  election_id:           [u8; 32]
  commitment_count:      u64
  last_root_update_slot: u64
  current_root:          [u8; 32]
  Total:                 80 bytes
```

### HSM deployment model

Three architectural options were considered for where the enclave physically lives relative to the polling booths.

**Single-booth model (rejected).** Each polling booth runs its own HSM holding only voters registered at that booth. You can vote only where you registered. This violates the "vote anywhere in the country" requirement and is a non-starter.

**Shared-booth model (rejected).** Every polling booth carries a full copy of all sealed voter state. Anyone can vote anywhere, but you end up with thousands of copies of the national secret state that need to stay consistent. Operationally nightmarish and a massive attack surface — compromising a single booth compromises everyone.

**National HSM cluster (chosen).** One logical HSM (replicated for availability) holds all sealed voter state. Polling booths are thin clients — biometric capture, UI, transaction relay — with no sensitive state resident on the booth itself. Biometric samples travel over a mutually-authenticated channel to the HSM cluster, which performs the match, unseals the voter's secrets, generates the vote proof and signature, and returns the signed transaction to the booth for relay to Solana.

This is the architecture banks use for POS card networks — distributed terminals plus central acquirer/scheme HSMs with DUKPT-style key management. The security model has been battle-tested across decades of production deployment. We are borrowing a working pattern, not inventing one.

For the hackathon, a single SoftHSM2 instance simulates the cluster, and booth clients connect to it over a local HTTP server. In production, the cluster would be a Thales/Utimaco/AWS CloudHSM array with replication, a geographically distributed deployment, operator quorums for administrative access, and quarterly key rotation ceremonies.

### Enclave boundary (software, SoftHSM2 + PKCS#11)

The enclave exposes four operations across its PKCS#11 surface:

1. `register(nin_hash, biometric_template, state_id, lga_id) -> commitment`
   Generates a fresh `identity_secret`, derives WOTS keys, computes commitment, seals secret and location inside the token, returns the commitment only.

2. `authenticate(biometric_live) -> session_handle`
   Performs biometric match against the sealed template; returns an opaque session handle with a short TTL.

3. `sign_vote(session_handle, election_id, candidate_id) -> (signature, nullifier, merkle_proof)`
   Checks the monotonic counter, loads `identity_secret` and location, constructs the vote message, signs with WOTS, computes the nullifier, retrieves the Merkle proof, returns all three. Increments the counter atomically.

4. `destroy_session(session_handle)`
   Wipes session memory.

The monotonic counter is implemented as a single file containing a `u64`, written via a write-temp-fsync-rename atomic sequence. The file is only readable by the enclave process. Each WOTS keypair is single-use (tree depth 1) so the counter is effectively a boolean per voter per election.

### Dashboard architecture

A lightweight Rust or Node server subscribes to the ballot program via Helius webhooks. On every new `BallotAccount` it extracts `(state_id, lga_id, candidate_id)` and updates an in-memory aggregation keyed by state. The frontend is a single HTML file with Leaflet.js, a Nigeria-state GeoJSON overlay (publicly available), and a Tailwind-styled table. A WebSocket pushes updates; the map and table re-render on every new vote.

No frontend framework. No Redux. The entire dashboard is about 300 lines of HTML + vanilla JS + a 200-line Rust aggregation server.

### Tally verifier

A standalone Rust CLI that takes a Solana RPC endpoint and an election ID, fetches every BallotAccount for that election, verifies every signature and every Merkle proof, counts nullifiers for double-vote detection, and outputs a signed audit report. Permissionless — any journalist, observer, or citizen can run this.

---

## Changelog

- **v0.1 (2026-04-18)** — Initial report. Attestor removed from trust model at all phases. ZK circuit scoped out of hackathon submission. 26-day timeline in progress in `TIMELINE.md`.
- **v0.1.1 (2026-04-18, same day)** — Added Pedersen-commitment equation and the explicit "not strictly required for demo, retained for upgrade path" rationale. Made the WOTS registry↔ballot lifecycle explicit; previously it was implied only. No architectural changes; clarifications only.
- **v0.1.2 (2026-04-18, same day)** — Corrected the hiding/binding framing: Pedersen is **perfectly hiding, computationally binding** (I had it inverted in v0.1.1). The corrected statement is important because it means a future quantum adversary could forge new openings but cannot de-anonymize old commitments — the right tradeoff for voter privacy.
- **v0.1.3 (2026-04-18, evening)** — Added HSM deployment model section (three options considered, national cluster chosen, banking POS PKI cited as reference). Reopened ZK as an active investigation with a bounded spike in Phase 1; see NOTES.md for the Day 2–3 spike plan and go/no-go gate. If the spike passes, subsequent report versions will document the Semaphore integration concretely.
