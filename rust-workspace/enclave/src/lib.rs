//! enclave — SoftHSM2 wrapper + monotonic counter + voter secrets.
//!
//! API surface (see PROJECT-PLAN.md "Enclave boundary"):
//!   register(nin_hash, biometric_template, state_id, lga_id) -> Commitment
//!   authenticate(biometric_live) -> SessionHandle
//!   sign_vote(session, election_id, candidate_id) -> (Signature, Nullifier, MerkleProof)
//!   destroy_session(session)
//!
//! Filled in starting Day 4 of TIMELINE.md.

#![allow(dead_code)]

pub mod counter;

pub struct Commitment(pub [u8; 32]);
pub struct Nullifier(pub [u8; 32]);
pub struct SessionHandle(pub u64);

pub fn register(
    _nin_hash: &[u8; 32],
    _biometric_template: &[u8],
    _state_id: u8,
    _lga_id: u16,
) -> anyhow::Result<Commitment> {
    anyhow::bail!("enclave::register not implemented — see TIMELINE.md Day 6")
}
