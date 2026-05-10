//! Voter credential issuance and pre-flight attestation verification.
//!
//! ## Sequencing within the enclave's `register()` entry point
//!
//! ```text
//!  1. Biometric match (software, against sealed template)
//!  2. ctx.create_registration_session(SLOT_VOTER, voter_id, biometric_hash)
//!  3. issue(session, credential_secret, state_id, lga_id, election_id, blinding)
//!       → VoterCredential { commitment, wrapped_msk, attestation_mac }
//!  4. Save VoterCredential to disk atomically (fsync-rename, same as counter)
//!     ← crash-safe: if the relayer dies here, step 5 can be retried from disk
//!  5. verify_attestation(session, &cred.commitment, election_id, &cred.attestation_mac)
//!       → must return true before we touch the network
//!  6. session.logout()
//!  7. Build and submit insert_commitment tx to Solana (~1-3 s round-trip)
//!  8. On Solana confirmation: mark the voter registered in the local DB
//!  9. On tx failure: retry step 7 with the same credential from disk —
//!     the commitment is deterministic once the blinding is saved, so
//!     re-issue is NOT needed; the same leaf will be re-inserted idempotently.
//! ```
//!
//! ## Why verify_attestation sits between issue and the tx
//!
//! Between step 3 and step 7 there is an unavoidable time gap (save, session
//! teardown, network).  `verify_attestation` closes the window where a
//! memory-safety bug or a compromised relayer process could swap the commitment
//! bytes before they reach the blockchain.  The HMAC re-check is cheap (<1 ms)
//! and runs inside the same authenticated HSM session as the issuance, before
//! any process boundary is crossed.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::commitment;
use crate::hsm::{HsmSession, LABEL_ATTESTATION, LABEL_KWRAP};

// ── Attestation message layout ────────────────────────────────────────────────
//
//   [0..14]  domain tag   b"IDV2-v1-attest"
//   [14..46] commitment   32-byte compressed Ristretto255 point
//   [46..54] election_id  u64 little-endian
//   total    54 bytes
//
const ATTEST_DOMAIN: &[u8] = b"IDV2-v1-attest";

fn attest_msg(commitment: &[u8; 32], election_id: u64) -> [u8; 54] {
    let mut msg = [0u8; 54];
    msg[0..14].copy_from_slice(ATTEST_DOMAIN);
    msg[14..46].copy_from_slice(commitment);
    msg[46..54].copy_from_slice(&election_id.to_le_bytes());
    msg
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Output of [`issue`].  Persisted to disk before any network call.
///
/// * `commitment`      — 32-byte compressed Ristretto255 Pedersen commitment.
///                       This is the Merkle leaf inserted by `insert_commitment`.
/// * `wrapped_msk`     — AES-KEY-WRAP-PAD encrypted voter MSK.  Stored on disk
///                       keyed by `SHA-256(NIN)`; only the HSM can decrypt it.
/// * `attestation_mac` — 32-byte `HMAC-SHA256(attest_key, attest_msg)`.
///                       Verified by [`verify_attestation`] before the tx is built.
/// * `state_id`        — State of the polling unit where registration occurred.
///                       Frozen at registration; used at vote time so the ballot
///                       is always counted under the correct geography.
/// * `lga_id`          — LGA of the polling unit where registration occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterCredential {
    pub commitment: [u8; 32],
    pub wrapped_msk: Vec<u8>,
    pub attestation_mac: Vec<u8>,
    pub state_id: u8,
    pub lga_id: u16,
    /// On-chain leaf index confirmed after successful insert_commitment tx.
    /// None means registration was never confirmed (retry required).
    #[serde(default)]
    pub leaf_index: Option<u64>,
}

impl VoterCredential {
    /// Atomically persist the credential to `path` using fsync-rename.
    ///
    /// If the process crashes after this call, the relayer can reload the
    /// credential and retry step 7 without re-running `issue()`.
    pub fn save_atomic(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec(self).context("serialise credential")?;
        let mut f = fs::File::create(&tmp).context("create tmp file")?;
        f.write_all(&bytes).context("write credential")?;
        f.sync_all().context("fsync credential")?;
        fs::rename(&tmp, path).context("rename credential into place")?;
        // fsync the parent directory so the rename is durable.
        if let Some(dir) = path.parent() {
            fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .context("fsync credential directory")?;
        }
        Ok(())
    }

    /// Load a previously persisted credential from `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read(path).context("read credential file")?;
        serde_json::from_slice(&bytes).context("deserialise credential")
    }

    /// Canonical disk path for a voter's credential file.
    ///
    /// `voter_id` is `SHA-256(NIN)`.  Stored in `base_dir/voter_id_hex.json`.
    pub fn path_for(base_dir: &Path, voter_id: &[u8; 32]) -> PathBuf {
        let hex: String = voter_id.iter().map(|b| format!("{b:02x}")).collect();
        base_dir.join(format!("{hex}.json"))
    }
}

// ── Issuance ──────────────────────────────────────────────────────────────────

/// Issue a voter credential inside an authenticated registration session.
///
/// This is step 3 in the sequencing above.  Requires K_wrap and the attestation
/// key to already exist in the token (created by the key ceremony).
///
/// `blinding` must be sampled from `Scalar::random(&mut OsRng)` by the caller
/// and saved alongside the credential if deterministic retry is needed.
pub fn issue(
    session: &HsmSession,
    credential_secret: &[u8; 32],
    state_id: u8,
    lga_id: u16,
    election_id: u64,
    blinding: &Scalar,
) -> anyhow::Result<VoterCredential> {
    // Look up the two persistent token objects created during key ceremony.
    let kwrap = session
        .require_by_label(LABEL_KWRAP)
        .context("K_wrap not found — run key ceremony first")?;
    let attest_key = session
        .require_by_label(LABEL_ATTESTATION)
        .context("attestation key not found — run key ceremony first")?;

    // Generate voter MSK as a session object (CKA_EXTRACTABLE=false).
    let msk = session.generate_voter_msk().context("MSK generation failed")?;

    // Wrap MSK under K_wrap for safe on-disk storage.
    let wrapped_msk = session.wrap_key(kwrap, msk).context("MSK wrap failed")?;

    // Compute Pedersen commitment in the enclave (commitment module).
    // state_id and lga_id are bound into the message scalar so location
    // is encoded in the commitment without exposing it directly.
    let cp = commitment::commit(credential_secret, state_id, lga_id, blinding);
    let commitment = *cp.as_bytes();

    // HSM signs commitment ‖ election_id → attestation_mac.
    let msg = attest_msg(&commitment, election_id);
    let attestation_mac = session
        .hmac_sign(attest_key, &msg)
        .context("attestation HMAC failed")?;

    Ok(VoterCredential { commitment, wrapped_msk, attestation_mac, state_id, lga_id, leaf_index: None })
}

// ── Client verification ───────────────────────────────────────────────────────

/// Verify the attestation MAC **before** constructing the `insert_commitment` tx.
///
/// This is step 5 in the sequencing above.  Must be called in the same
/// authenticated HSM session as [`issue`], after the credential is saved to
/// disk but before any network call.
///
/// Returns `true` iff `attestation_mac` was produced by the HSM for exactly
/// this `commitment` and `election_id`.  A `false` result means the commitment
/// bytes were tampered with after issuance — abort the registration flow.
pub fn verify_attestation(
    session: &HsmSession,
    commitment: &[u8; 32],
    election_id: u64,
    attestation_mac: &[u8],
) -> anyhow::Result<bool> {
    let attest_key = session
        .require_by_label(LABEL_ATTESTATION)
        .context("attestation key not found")?;
    let msg = attest_msg(commitment, election_id);
    session.hmac_verify(attest_key, &msg, attestation_mac)
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // ── Pure-unit tests (no HSM required) ────────────────────────────────────

    #[test]
    fn attest_msg_layout_correct() {
        let c = [0x01u8; 32];
        let eid: u64 = 0x0102030405060708;
        let msg = attest_msg(&c, eid);

        assert_eq!(&msg[0..14], ATTEST_DOMAIN);
        assert_eq!(&msg[14..46], &c);
        assert_eq!(&msg[46..54], &eid.to_le_bytes());
        assert_eq!(msg.len(), 54);
    }

    #[test]
    fn attest_msg_domain_tag_frozen() {
        assert_eq!(ATTEST_DOMAIN, b"IDV2-v1-attest");
    }

    #[test]
    fn attest_msg_differs_by_commitment() {
        assert_ne!(attest_msg(&[0x01u8; 32], 1), attest_msg(&[0x02u8; 32], 1));
    }

    #[test]
    fn attest_msg_differs_by_election_id() {
        assert_ne!(attest_msg(&[0x01u8; 32], 1), attest_msg(&[0x01u8; 32], 2));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let cred = VoterCredential {
            commitment: [0x01u8; 32],
            wrapped_msk: vec![0x02u8; 48],
            attestation_mac: vec![0x03u8; 32],
            state_id: 1,
            lga_id: 101,
            leaf_index: Some(0),
        };
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("test_cred.json");
        cred.save_atomic(&path).expect("save");

        let loaded = VoterCredential::load(&path).expect("load");
        assert_eq!(loaded.commitment, cred.commitment);
        assert_eq!(loaded.wrapped_msk, cred.wrapped_msk);
        assert_eq!(loaded.attestation_mac, cred.attestation_mac);
    }

    #[test]
    fn path_for_is_deterministic() {
        let voter = [0x01u8; 32];
        let dir = std::path::Path::new("/tmp/creds");
        let p1 = VoterCredential::path_for(dir, &voter);
        let p2 = VoterCredential::path_for(dir, &voter);
        assert_eq!(p1, p2);
    }

    #[test]
    fn path_for_differs_by_voter() {
        let dir = std::path::Path::new("/tmp/creds");
        let p1 = VoterCredential::path_for(dir, &[0x01u8; 32]);
        let p2 = VoterCredential::path_for(dir, &[0x02u8; 32]);
        assert_ne!(p1, p2);
    }

    // ── Integration tests (require SoftHSM2 + key ceremony) ──────────────────
    //
    // Before running:
    //   export SOFTHSM2_LIB=/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so
    //   # Init tokens, generate K_wrap and attestation key via idv2-admin (not yet built).
    //   # For now you can prime the token manually:
    //   #   cargo test -p enclave -- --include-ignored integration_prime_token 2>&1
    //   cargo test -p enclave -- --include-ignored 2>&1

    #[test]
    #[ignore]
    fn integration_issue_and_verify_roundtrip() {
        use crate::hsm::HsmContext;
        use rand::rngs::OsRng;

        let ctx = HsmContext::from_env().expect("context");
        let voter_id = [0x01u8; 32];
        let bio_hash = [0xabu8; 32];
        let session = ctx
            .create_registration_session(crate::hsm::SLOT_VOTER, &voter_id, &bio_hash)
            .expect("registration session");

        let credential_secret = [0x42u8; 32];
        let blinding = Scalar::random(&mut OsRng);
        let cred = issue(&session, &credential_secret, 25, 537, 1, &blinding)
            .expect("issue credential");

        assert_eq!(cred.commitment.len(), 32);
        assert!(!cred.wrapped_msk.is_empty());
        assert_eq!(cred.attestation_mac.len(), 32);

        // Step 4: persist before touching network.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = VoterCredential::path_for(dir.path(), &voter_id);
        cred.save_atomic(&path).expect("save credential");

        // Step 5: verify before building the insert_commitment tx.
        let valid = verify_attestation(&session, &cred.commitment, 1, &cred.attestation_mac)
            .expect("verify");
        assert!(valid, "correct MAC must verify");

        // Tamper check.
        let mut bad = cred.commitment;
        bad[0] ^= 0x01;
        let invalid = verify_attestation(&session, &bad, 1, &cred.attestation_mac)
            .expect("verify tampered");
        assert!(!invalid, "tampered commitment must not verify");

        session.logout().expect("logout");
    }

    #[test]
    #[ignore]
    fn integration_wrong_election_id_rejected() {
        use crate::hsm::HsmContext;
        use rand::rngs::OsRng;

        let ctx = HsmContext::from_env().expect("context");
        let voter_id = [0x01u8; 32];
        let bio_hash = [0xabu8; 32];
        let session = ctx
            .create_registration_session(crate::hsm::SLOT_VOTER, &voter_id, &bio_hash)
            .expect("session");

        let cred = issue(&session, &[0x42u8; 32], 25, 537, 1, &Scalar::random(&mut OsRng))
            .expect("issue");

        let wrong = verify_attestation(&session, &cred.commitment, 999, &cred.attestation_mac)
            .expect("verify wrong eid");
        assert!(!wrong, "wrong election_id must not verify");

        session.logout().expect("logout");
    }
}
