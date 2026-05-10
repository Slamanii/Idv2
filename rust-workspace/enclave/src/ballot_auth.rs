//! Ballot authorization: the HSM signs `nullifier ‖ commitment` under the
//! election's Ed25519 ballot-signing key.
//!
//! ## Message format (78 bytes)
//!
//!   `b"IDV2-v1-ballot" ‖ nullifier[32] ‖ commitment[32]`
//!
//! ## On-chain verification (ballot::cast)
//!
//! The ballot program verifies the signature via the native Solana Ed25519
//! program.  The transaction must include a leading Ed25519 program instruction
//! (ix[0]) that attests to the signature before ballot::cast (ix[1]).  The
//! ballot program reads the Instructions sysvar to confirm this.
//!
//! See `programs/ballot/src/instructions.rs` for the verification stub and
//! the full implementation plan.
//!
//! ## Key management
//!
//! The signing keypair lives in the HSM token under label `LABEL_ED25519_SIGN`.
//! Its public key is stored on-chain in `ElectionAccount.aggregation_pubkey`.
//! Run `cargo run -p enclave --bin key_ceremony` to generate it.

use crate::hsm::HsmSession;
use cryptoki::object::ObjectHandle;
use anyhow::Context;

const BALLOT_DOMAIN: &[u8] = b"IDV2-v1-ballot"; // 14 bytes

/// Authorisation payload returned by the HSM for a single vote cast.
#[derive(Debug, Clone)]
pub struct BallotAuthorization {
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
    /// Ed25519 signature over `ballot_message(nullifier, commitment)`.
    pub signature: [u8; 64],
    /// Public key that produced the signature.
    /// Must match `ElectionAccount.aggregation_pubkey` for on-chain acceptance.
    pub authority_pubkey: [u8; 32],
}

/// Build the 78-byte message that the HSM signs.
///
/// Deterministic; safe to call off the HSM as well (e.g., for tests or the
/// client-side verifier before broadcasting).
pub fn ballot_message(nullifier: &[u8; 32], commitment: &[u8; 32]) -> [u8; 78] {
    let mut msg = [0u8; 78];
    msg[0..14].copy_from_slice(BALLOT_DOMAIN);
    msg[14..46].copy_from_slice(nullifier);
    msg[46..78].copy_from_slice(commitment);
    msg
}

/// Produce a `BallotAuthorization` for one vote cast.
///
/// - `priv_key` — handle to the Ed25519 private key (from `LABEL_ED25519_SIGN`).
/// - `pub_key`  — handle to the matching public key (to extract the raw 32 bytes).
///
/// Obtain handles via `session.require_priv_by_label(LABEL_ED25519_SIGN)` and
/// `session.require_pub_by_label(LABEL_ED25519_SIGN)`.
pub fn authorize_ballot(
    session: &HsmSession,
    priv_key: ObjectHandle,
    pub_key: ObjectHandle,
    nullifier: &[u8; 32],
    commitment: &[u8; 32],
) -> anyhow::Result<BallotAuthorization> {
    let msg = ballot_message(nullifier, commitment);
    let signature = session
        .eddsa_sign(priv_key, &msg)
        .context("EdDSA ballot sign failed")?;
    let authority_pubkey = session
        .get_ed25519_pubkey(pub_key)
        .context("get Ed25519 pubkey failed")?;
    Ok(BallotAuthorization {
        nullifier: *nullifier,
        commitment: *commitment,
        signature,
        authority_pubkey,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ballot_message_length() {
        let msg = ballot_message(&[1u8; 32], &[2u8; 32]);
        assert_eq!(msg.len(), 78);
    }

    #[test]
    fn ballot_message_domain_prefix() {
        let msg = ballot_message(&[0u8; 32], &[0u8; 32]);
        assert_eq!(&msg[..14], b"IDV2-v1-ballot");
    }

    #[test]
    fn ballot_message_embeds_nullifier_and_commitment() {
        let nullifier  = [0xaau8; 32];
        let commitment = [0xbbu8; 32];
        let msg = ballot_message(&nullifier, &commitment);
        assert_eq!(&msg[14..46], &nullifier);
        assert_eq!(&msg[46..78], &commitment);
    }

    #[test]
    fn ballot_message_is_deterministic() {
        let n = [0x01u8; 32];
        let c = [0x02u8; 32];
        assert_eq!(ballot_message(&n, &c), ballot_message(&n, &c));
    }

    #[test]
    fn ballot_message_differs_by_nullifier() {
        let c = [0x01u8; 32];
        assert_ne!(ballot_message(&[0xaau8; 32], &c), ballot_message(&[0xbbu8; 32], &c));
    }

    #[test]
    fn ballot_message_differs_by_commitment() {
        let n = [0x01u8; 32];
        assert_ne!(ballot_message(&n, &[0xaau8; 32]), ballot_message(&n, &[0xbbu8; 32]));
    }

    // ── Integration (requires SoftHSM2 + key ceremony) ────────────────────────
    //
    // Before running:
    //   source scripts/setup-softhsm.sh
    //   cargo run -p enclave --bin key_ceremony
    //
    // Then: cargo test -p enclave -- --include-ignored 2>&1

    #[test]
    #[ignore]
    fn integration_authorize_ballot_roundtrip() {
        use crate::hsm::{HsmContext, LABEL_ED25519_SIGN, SLOT_ROOT};

        let ctx = HsmContext::from_env().expect("ctx");
        let session = ctx.open_session(SLOT_ROOT, "1234").expect("session");

        let priv_handle = session
            .require_priv_by_label(LABEL_ED25519_SIGN)
            .expect("private key must exist — run key ceremony first");
        let pub_handle = session
            .require_pub_by_label(LABEL_ED25519_SIGN)
            .expect("public key must exist — run key ceremony first");

        let nullifier  = [0x10u8; 32];
        let commitment = [0x20u8; 32];

        let auth = authorize_ballot(&session, priv_handle, pub_handle, &nullifier, &commitment)
            .expect("authorize_ballot must succeed");

        assert_eq!(auth.nullifier, nullifier);
        assert_eq!(auth.commitment, commitment);
        assert_eq!(auth.signature.len(), 64);
        assert_ne!(auth.authority_pubkey, [0u8; 32], "pubkey must be non-zero");
        assert_eq!(ballot_message(&nullifier, &commitment).len(), 78);

        session.logout().expect("logout");
    }
}
