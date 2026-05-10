//! enclave — SoftHSM2 wrapper + monotonic counter + voter secrets.
//!
//! ## Module layout
//!
//!   `commitment`  Ristretto255 Pedersen commitment (C = m·G + r·H)
//!   `nullifier`   SHA-3-256 nullifier derivation
//!   `hsm`         PKCS#11 session management, key generation, C_Sign wrappers
//!   `issuance`    Voter credential issuance + pre-flight attestation verification
//!   `counter`     Software monotonic counter (fsync-rename)
//!
//! ## Top-level API
//!
//!   `register(nin_hash, biometric_template, state_id, lga_id) -> Commitment`
//!   `sign_vote(session, election_id, candidate_id) -> (Signature, Nullifier, MerkleProof)`
//!
//! ## Credential issuance sequence (register)
//!
//!   1. Biometric match (software)
//!   2. `hsm::HsmContext::create_registration_session(slot, voter_id, biometric_hash)`
//!   3. `issuance::issue(session, credential_secret, state_id, lga_id, election_id, blinding)`
//!        → `VoterCredential { commitment, wrapped_msk, attestation_mac }`
//!   4. `VoterCredential::save_atomic(path)`   ← crash-safe before any network call
//!   5. `issuance::verify_attestation(session, commitment, election_id, mac)` → must be true
//!   6. `session.logout()`
//!   7. Build + submit `insert_commitment` tx to Solana
//!
//! ## Voting sequence (sign_vote)
//!
//!   1. Biometric match (software)
//!   2. `hsm::HsmContext::open_voting_session(slot, voter_id, biometric_hash)`
//!   3. Load `VoterCredential` from disk; `session.unwrap_key(kwrap, wrapped_msk)`
//!   4. `nullifier::derive(credential_secret, election_id)` → nullifier
//!   5. Build and sign the ballot payload via the HSM

#![allow(dead_code)]

pub mod ballot_auth;
pub mod commitment;
pub mod counter;
pub mod credential;
pub mod hsm;
pub mod issuance;
pub mod nullifier;

pub struct Commitment(pub [u8; 32]);
pub struct Nullifier(pub [u8; 32]);
pub struct SessionHandle(pub u64);

pub fn register(
    _nin_hash: &[u8; 32],
    _biometric_template: &[u8],
    _state_id: u8,
    _lga_id: u16,
) -> anyhow::Result<Commitment> {
    anyhow::bail!("enclave::register not yet wired — modules are ready; see issuance::issue")
}
