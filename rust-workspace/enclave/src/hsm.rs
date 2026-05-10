//! PKCS#11 session management and cryptographic operation wrappers.
//!
//! Two session-open paths:
//!
//!   `open_session(slot, pin_str)`
//!     Authority / operator path — takes a plaintext PIN string.  Used by
//!     `idv2-admin` for key ceremony (K_wrap generation, attestation key setup).
//!
//!   `open_session_biometric(slot, voter_id, biometric_hash)`
//!     Voter path — the PKCS#11 user PIN is HKDF-derived from the biometric
//!     hash.  Without a correct live biometric the derived PIN is wrong and
//!     `C_Login` returns `CKR_PIN_INCORRECT`.  The biometric IS the secret that
//!     unlocks the session; the label/key/message are purely operational params
//!     that only matter once the session is already open.
//!
//! Library path resolution order:
//!   1. `SOFTHSM2_LIB` environment variable (highest priority — CI / devbox)
//!   2. macOS Homebrew default   `/opt/homebrew/…/libsofthsm2.so`
//!   3. Linux system default     `/usr/lib/softhsm/libsofthsm2.so`
//!
//! SoftHSM2 token config is read by the library itself from `SOFTHSM2_CONF`
//! or `~/.config/softhsm2/softhsm2.conf` — no additional setup needed here.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use hkdf::Hkdf;
use sha2::Sha256;

// ── Slot indices ──────────────────────────────────────────────────────────────
pub const SLOT_ROOT:  usize = 0; // idv2-root   — K_wrap, K_agg_sign
pub const SLOT_BOOTH: usize = 1; // idv2-booth  — transport keys
pub const SLOT_VOTER: usize = 2; // idv2-voter  — voter MSKs (sharded)

// ── Well-known token-object labels ────────────────────────────────────────────
pub const LABEL_KWRAP:        &[u8] = b"idv2-kwrap-v1";
pub const LABEL_ATTESTATION:  &[u8] = b"idv2-attestation-v1";
pub const LABEL_ED25519_SIGN: &[u8] = b"idv2-ballot-sign-v1";

// Ed25519 curve OID (1.3.101.112) in DER: OID tag 06, length 03, bytes 2B 65 70
const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

// ── Library resolution ────────────────────────────────────────────────────────

/// Return the PKCS#11 library path.
///
/// Checks `SOFTHSM2_LIB` first; falls back to the platform default.
/// Set the env var in `.env` or the shell profile for the active devbox:
///
/// ```sh
/// export SOFTHSM2_LIB=/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so
/// ```
pub fn lib_path() -> PathBuf {
    if let Ok(p) = std::env::var("SOFTHSM2_LIB") {
        return PathBuf::from(p);
    }
    if cfg!(target_os = "macos") {
        // Homebrew arm64 default — matches 2.7.0 installed on this machine.
        PathBuf::from("/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so")
    } else {
        PathBuf::from("/usr/lib/softhsm/libsofthsm2.so")
    }
}

// ── Biometric → PIN derivation ────────────────────────────────────────────────

/// Derive a 32-byte PKCS#11 user PIN from a biometric hash and voter id.
///
/// `PIN = HKDF-SHA256(ikm=biometric_hash, salt=voter_id, info="idv2:pkcs11-pin:v1")`
///
/// The derived PIN is hex-encoded (64 ASCII chars) before being passed to
/// `C_Login` so it is always valid UTF-8.  A wrong biometric → wrong PIN →
/// `C_Login` returns `CKR_PIN_INCORRECT`; the session never opens.
fn derive_pin(biometric_hash: &[u8; 32], voter_id: &[u8; 32]) -> AuthPin {
    let hk = Hkdf::<Sha256>::new(Some(voter_id.as_ref()), biometric_hash.as_ref());
    let mut raw = [0u8; 32];
    hk.expand(b"idv2:pkcs11-pin:v1", &mut raw)
        .expect("HKDF output fits 32 bytes");
    // Hex-encode so the pin bytes are valid UTF-8 as required by CK_UTF8CHAR.
    let pin_str: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    AuthPin::new(pin_str)
}

// ── Context ───────────────────────────────────────────────────────────────────

/// Loaded and initialized PKCS#11 library.  Construct once at process start.
pub struct HsmContext {
    pkcs11: Pkcs11,
}

impl HsmContext {
    /// Load the PKCS#11 library at `lib_path` and call `C_Initialize`.
    pub fn new(lib_path: &Path) -> anyhow::Result<Self> {
        let pkcs11 = Pkcs11::new(lib_path).context("failed to load PKCS#11 library")?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .context("C_Initialize failed")?;
        Ok(Self { pkcs11 })
    }

    /// Convenience constructor — resolves the library path via [`lib_path`].
    pub fn from_env() -> anyhow::Result<Self> {
        Self::new(&lib_path())
    }

    fn nth_slot(&self, index: usize) -> anyhow::Result<cryptoki::slot::Slot> {
        self.pkcs11
            .get_slots_with_initialized_token()
            .context("C_GetSlotList failed")?
            .into_iter()
            .nth(index)
            .ok_or_else(|| anyhow!("no initialized token at slot index {index}"))
    }

    // ── Session-open paths ────────────────────────────────────────────────────

    /// **Authority / key-ceremony path** — open a session with a plaintext PIN
    /// string.  Used by `idv2-admin` for K_wrap and attestation-key generation.
    /// Never called from the voter-facing code paths.
    pub fn open_session(&self, slot_index: usize, pin: &str) -> anyhow::Result<HsmSession> {
        self.open_raw(slot_index, &AuthPin::new(pin.to_string()))
    }

    /// **Registration path** — open a session that will generate new key material.
    ///
    /// Called once per voter at first registration.  The session is used to
    /// generate a fresh MSK, wrap it under K_wrap, compute the Pedersen
    /// commitment, and produce the attestation MAC.  The biometric IS the
    /// credential: `C_Login` uses a PIN derived from the biometric hash, so a
    /// failed or spoofed biometric scan produces the wrong PIN and the session
    /// never opens.
    ///
    /// * `voter_id`       — `SHA-256(NIN)`, HKDF salt (unique PIN per voter).
    /// * `biometric_hash` — SHA-256 of the live biometric match result.
    pub fn create_registration_session(
        &self,
        slot_index: usize,
        voter_id: &[u8; 32],
        biometric_hash: &[u8; 32],
    ) -> anyhow::Result<HsmSession> {
        let pin = derive_pin(biometric_hash, voter_id);
        self.open_raw(slot_index, &pin)
    }

    /// **Voting / ballot-cast path** — open a session that will unwrap an
    /// existing MSK and derive the signing material for a single vote.
    ///
    /// Called at every polling booth visit.  The session is used to unwrap the
    /// voter's saved `wrapped_msk`, derive the nullifier, and produce the
    /// vote payload.  Same biometric-PIN mechanism as `create_registration_session`;
    /// the distinction is that no new key material is ever generated here.
    ///
    /// * `voter_id`       — `SHA-256(NIN)`.
    /// * `biometric_hash` — SHA-256 of the live biometric match result.
    pub fn open_voting_session(
        &self,
        slot_index: usize,
        voter_id: &[u8; 32],
        biometric_hash: &[u8; 32],
    ) -> anyhow::Result<HsmSession> {
        let pin = derive_pin(biometric_hash, voter_id);
        self.open_raw(slot_index, &pin)
    }

    fn open_raw(&self, slot_index: usize, pin: &AuthPin) -> anyhow::Result<HsmSession> {
        let slot = self.nth_slot(slot_index)?;
        let session = self
            .pkcs11
            .open_rw_session(slot)
            .context("C_OpenSession failed")?;
        session
            .login(UserType::User, Some(pin))
            .context("C_Login failed — wrong PIN or biometric hash")?;
        Ok(HsmSession { inner: session })
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// Authenticated PKCS#11 session.
///
/// Drop closes the session (`C_CloseSession`); call [`logout`] first to
/// also call `C_Logout` and shrink the authentication window.
pub struct HsmSession {
    inner: Session,
}

impl HsmSession {
    // ── Key generation ────────────────────────────────────────────────────────

    /// Generate a 32-byte generic-secret voter MSK as a **session object**.
    /// The caller must wrap it before the session closes; the raw key material
    /// never leaves the HSM.
    pub fn generate_voter_msk(&self) -> anyhow::Result<ObjectHandle> {
        let attrs = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32_u64.into()),
            Attribute::Token(false),        // session-only — wrap before closing
            Attribute::Sensitive(true),
            // Must be true so C_WrapKey succeeds; Sensitive=true prevents plaintext export.
            Attribute::Extractable(true),
            Attribute::Derive(true),
        ];
        self.inner
            .generate_key(&Mechanism::GenericSecretKeyGen, &attrs)
            .context("C_GenerateKey (voter MSK) failed")
    }

    /// Generate a persistent AES-256 key-wrapping key (`CKA_WRAP + CKA_UNWRAP`).
    ///
    /// Intended for the root-slot K_wrap.  Run once during the key ceremony;
    /// the object persists in the token across sessions.
    pub fn generate_wrap_key(&self, label: &[u8]) -> anyhow::Result<ObjectHandle> {
        let attrs = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(32_u64.into()),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
            Attribute::Label(label.to_vec()),
        ];
        self.inner
            .generate_key(&Mechanism::AesKeyGen, &attrs)
            .context("C_GenerateKey (K_wrap) failed")
    }

    /// Generate a persistent 32-byte HMAC attestation key
    /// (`CKA_SIGN + CKA_VERIFY`).
    ///
    /// Signs `commitment ‖ election_id` at voter-credential issuance time.
    /// Run once during the key ceremony.
    pub fn generate_attestation_key(&self, label: &[u8]) -> anyhow::Result<ObjectHandle> {
        let attrs = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32_u64.into()),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Label(label.to_vec()),
        ];
        self.inner
            .generate_key(&Mechanism::GenericSecretKeyGen, &attrs)
            .context("C_GenerateKey (attestation key) failed")
    }

    // ── Key wrap / unwrap (CKM_AES_KEY_WRAP_PAD) ─────────────────────────────

    /// Wrap `key` under `wrap_key`.  Returns the encrypted blob for disk
    /// storage.  Never exposes the raw key bytes.
    pub fn wrap_key(
        &self,
        wrap_key: ObjectHandle,
        key: ObjectHandle,
    ) -> anyhow::Result<Vec<u8>> {
        self.inner
            .wrap_key(&Mechanism::AesKeyWrapPad, wrap_key, key)
            .context("C_WrapKey failed")
    }

    /// Unwrap a blob produced by [`wrap_key`] into a session-scoped handle with
    /// `CKA_DERIVE=true` and `CKA_EXTRACTABLE=false`.
    pub fn unwrap_key(
        &self,
        wrap_key: ObjectHandle,
        wrapped: &[u8],
    ) -> anyhow::Result<ObjectHandle> {
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
        ];
        self.inner
            .unwrap_key(&Mechanism::AesKeyWrapPad, wrap_key, wrapped, &template)
            .context("C_UnwrapKey failed")
    }

    // ── C_Sign / C_Verify wrappers (HMAC-SHA256) ──────────────────────────────

    /// Compute `HMAC-SHA256(key, message)` via `C_Sign`.  Returns 32 bytes.
    pub fn hmac_sign(&self, key: ObjectHandle, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.inner
            .sign(&Mechanism::Sha256Hmac, key, message)
            .context("C_Sign (HMAC-SHA256) failed")
    }

    /// Constant-time verify that `expected_mac == HMAC-SHA256(key, message)`.
    ///
    /// Re-computes via `C_Sign` rather than calling `C_Verify` directly, which
    /// avoids vendor-specific `CKR_SIGNATURE_INVALID` handling differences.
    pub fn hmac_verify(
        &self,
        key: ObjectHandle,
        message: &[u8],
        expected_mac: &[u8],
    ) -> anyhow::Result<bool> {
        let computed = self.hmac_sign(key, message)?;
        if computed.len() != expected_mac.len() {
            return Ok(false);
        }
        // Fold all differing bits — exits only after scanning every byte.
        let diff = computed
            .iter()
            .zip(expected_mac)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        Ok(diff == 0)
    }

    // ── Object lookup ─────────────────────────────────────────────────────────

    /// Return the first token object whose `CKA_LABEL == label`, or `None`.
    pub fn find_by_label(&self, label: &[u8]) -> anyhow::Result<Option<ObjectHandle>> {
        let hits = self
            .inner
            .find_objects(&[Attribute::Label(label.to_vec())])
            .context("C_FindObjects failed")?;
        Ok(hits.into_iter().next())
    }

    /// Like [`find_by_label`] but errors if the object is absent.
    pub fn require_by_label(&self, label: &[u8]) -> anyhow::Result<ObjectHandle> {
        self.find_by_label(label)?.ok_or_else(|| {
            anyhow!(
                "PKCS#11 object '{}' not found — run the key ceremony first",
                String::from_utf8_lossy(label)
            )
        })
    }

    /// Find the **public key** with `CKA_LABEL == label`.
    ///
    /// When a keypair is stored under the same label, searching by label alone
    /// may return either half.  This method additionally filters by
    /// `CKA_CLASS = CKO_PUBLIC_KEY` to guarantee the public key is returned.
    pub fn find_pub_by_label(
        &self,
        label: &[u8],
    ) -> anyhow::Result<Option<ObjectHandle>> {
        let hits = self
            .inner
            .find_objects(&[
                Attribute::Label(label.to_vec()),
                Attribute::Class(ObjectClass::PUBLIC_KEY),
            ])
            .context("C_FindObjects (pub key) failed")?;
        Ok(hits.into_iter().next())
    }

    /// Like [`find_pub_by_label`] but errors if absent.
    pub fn require_pub_by_label(&self, label: &[u8]) -> anyhow::Result<ObjectHandle> {
        self.find_pub_by_label(label)?.ok_or_else(|| {
            anyhow!(
                "PKCS#11 public key '{}' not found — run the key ceremony first",
                String::from_utf8_lossy(label)
            )
        })
    }

    /// Find the **private key** with `CKA_LABEL == label`.
    pub fn find_priv_by_label(
        &self,
        label: &[u8],
    ) -> anyhow::Result<Option<ObjectHandle>> {
        let hits = self
            .inner
            .find_objects(&[
                Attribute::Label(label.to_vec()),
                Attribute::Class(ObjectClass::PRIVATE_KEY),
            ])
            .context("C_FindObjects (priv key) failed")?;
        Ok(hits.into_iter().next())
    }

    /// Like [`find_priv_by_label`] but errors if absent.
    pub fn require_priv_by_label(&self, label: &[u8]) -> anyhow::Result<ObjectHandle> {
        self.find_priv_by_label(label)?.ok_or_else(|| {
            anyhow!(
                "PKCS#11 private key '{}' not found — run the key ceremony first",
                String::from_utf8_lossy(label)
            )
        })
    }

    // ── Ed25519 (CKM_ECDSA_EDWARDS) ──────────────────────────────────────────

    /// Generate a persistent Ed25519 signing keypair.
    ///
    /// Returns `(public_handle, private_handle)`.  Both objects are written to
    /// token storage so they survive across sessions.  Run once during the key
    /// ceremony; the private key is sensitive and non-extractable.
    pub fn generate_ed25519_keypair(
        &self,
        label: &[u8],
    ) -> anyhow::Result<(ObjectHandle, ObjectHandle)> {
        // SoftHSM2 2.7 rules for CKM_EC_EDWARDS_KEY_PAIR_GEN:
        //   • CKA_EC_PARAMS is REQUIRED in the public template (identifies curve).
        //   • CKA_EC_PARAMS in the private template → CKR_ATTRIBUTE_READ_ONLY.
        //   • CKA_CLASS / CKA_KEY_TYPE in either template → CKR_ATTRIBUTE_READ_ONLY.
        let pub_template = [
            Attribute::EcParams(ED25519_OID_DER.to_vec()),
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::Label(label.to_vec()),
        ];
        let priv_template = [
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Label(label.to_vec()),
        ];
        self.inner
            .generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &pub_template,
                &priv_template,
            )
            .context("C_GenerateKeyPair (Ed25519) failed")
    }

    /// Extract the 32-byte Ed25519 public key from the `CKA_EC_POINT` attribute.
    ///
    /// SoftHSM2 encodes the EC point as a DER OCTET STRING.  Three observed
    /// encodings are handled:
    ///   32 bytes  — raw key (no header)
    ///   34 bytes  — `04 20 <32B>` (uncompressed point, direct)
    ///   36 bytes  — `04 22 04 20 <32B>` (OCTET STRING wrapping uncompressed)
    pub fn get_ed25519_pubkey(&self, pub_handle: ObjectHandle) -> anyhow::Result<[u8; 32]> {
        let attrs = self
            .inner
            .get_attributes(pub_handle, &[AttributeType::EcPoint])
            .context("C_GetAttributeValue (EcPoint) failed")?;
        for attr in attrs {
            if let Attribute::EcPoint(bytes) = attr {
                return match bytes.len() {
                    32 => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&bytes);
                        Ok(k)
                    }
                    34 if bytes[0] == 0x04 && bytes[1] == 0x20 => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&bytes[2..]);
                        Ok(k)
                    }
                    36 if bytes[0] == 0x04 && bytes[1] == 0x22
                            && bytes[2] == 0x04 && bytes[3] == 0x20 =>
                    {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&bytes[4..]);
                        Ok(k)
                    }
                    _ => anyhow::bail!(
                        "unexpected EC_POINT encoding len={}, head={:02x?}",
                        bytes.len(),
                        &bytes[..bytes.len().min(4)]
                    ),
                };
            }
        }
        anyhow::bail!("EC_POINT attribute not returned by PKCS#11 token")
    }

    /// Sign `message` with the Ed25519 private key at `priv_handle`.
    ///
    /// Returns a 64-byte raw signature `r ‖ s` via `C_Sign(CKM_EDDSA)`.
    pub fn eddsa_sign(
        &self,
        priv_handle: ObjectHandle,
        message: &[u8],
    ) -> anyhow::Result<[u8; 64]> {
        let sig_bytes = self
            .inner
            .sign(&Mechanism::Eddsa, priv_handle, message)
            .context("C_Sign (EdDSA) failed")?;
        sig_bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("EdDSA signature is {} bytes, expected 64", v.len()))
    }

    // ── Session teardown ──────────────────────────────────────────────────────

    /// `C_Logout` then drop (`C_CloseSession`).
    ///
    /// Call this after every voting operation to shrink the authenticated window.
    pub fn logout(self) -> anyhow::Result<()> {
        self.inner.logout().context("C_Logout failed")?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure-unit tests (no HSM required) ────────────────────────────────────

    #[test]
    fn derive_pin_is_deterministic() {
        let voter = [0x01u8; 32];
        let bio = [0xabu8; 32];
        // Same inputs → same AuthPin content.
        // We can't inspect AuthPin internals directly, but we can derive twice
        // and confirm the HKDF output is consistent.
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&voter), &bio);
        hk.expand(b"idv2:pkcs11-pin:v1", &mut out1).unwrap();
        hk.expand(b"idv2:pkcs11-pin:v1", &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn derive_pin_differs_by_voter_id() {
        let bio = [0xabu8; 32];
        let voter_a = [0x01u8; 32];
        let voter_b = [0x02u8; 32];
        let mut pin_a = [0u8; 32];
        let mut pin_b = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&voter_a), &bio)
            .expand(b"idv2:pkcs11-pin:v1", &mut pin_a)
            .unwrap();
        Hkdf::<Sha256>::new(Some(&voter_b), &bio)
            .expand(b"idv2:pkcs11-pin:v1", &mut pin_b)
            .unwrap();
        assert_ne!(pin_a, pin_b, "different voters must have different PINs");
    }

    #[test]
    fn derive_pin_differs_by_biometric() {
        let voter = [0x01u8; 32];
        let bio_a = [0xabu8; 32];
        let bio_b = [0xcdu8; 32];
        let mut pin_a = [0u8; 32];
        let mut pin_b = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&voter), &bio_a)
            .expand(b"idv2:pkcs11-pin:v1", &mut pin_a)
            .unwrap();
        Hkdf::<Sha256>::new(Some(&voter), &bio_b)
            .expand(b"idv2:pkcs11-pin:v1", &mut pin_b)
            .unwrap();
        assert_ne!(pin_a, pin_b, "different biometrics must produce different PINs");
    }

    #[test]
    fn ct_hmac_compare_all_equal() {
        let a = [0xabu8; 32];
        let b = [0xabu8; 32];
        let diff = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        assert_eq!(diff, 0);
    }

    #[test]
    fn ct_hmac_compare_one_bit_off() {
        let a = [0x00u8; 32];
        let mut b = [0x00u8; 32];
        b[15] = 0x01;
        let diff = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        assert_ne!(diff, 0);
    }

    #[test]
    fn lib_path_prefers_env_var() {
        std::env::set_var("SOFTHSM2_LIB", "/custom/libsofthsm2.so");
        assert_eq!(lib_path(), std::path::PathBuf::from("/custom/libsofthsm2.so"));
        std::env::remove_var("SOFTHSM2_LIB");
    }

    // ── Integration tests (require SoftHSM2 + initialized tokens) ────────────
    //
    // Before running:
    //   export SOFTHSM2_LIB=/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so
    //   softhsm2-util --init-token --slot 0 --label idv2-root  --pin 1234 --so-pin 0000
    //   softhsm2-util --init-token --slot 1 --label idv2-booth --pin 1234 --so-pin 0000
    //   softhsm2-util --init-token --slot 2 --label idv2-voter --pin 1234 --so-pin 0000
    //
    // Then: cargo test -p enclave -- --include-ignored 2>&1

    #[test]
    #[ignore]
    fn integration_open_and_close_session() {
        let ctx = HsmContext::from_env().expect("context");
        let session = ctx.open_session(SLOT_ROOT, "1234").expect("session");
        session.logout().expect("logout");
    }

    #[test]
    #[ignore]
    fn integration_registration_session_correct_hash_opens() {
        let ctx = HsmContext::from_env().expect("context");
        let voter_id = [0x01u8; 32];
        let bio_hash = [0xabu8; 32]; // same hash used when the voter-slot PIN was initialised
        let _session = ctx
            .create_registration_session(SLOT_VOTER, &voter_id, &bio_hash)
            .expect("registration session must open with the correct biometric hash");
    }

    #[test]
    #[ignore]
    fn integration_registration_session_wrong_hash_rejected() {
        let ctx = HsmContext::from_env().expect("context");
        let voter_id = [0x01u8; 32];
        let wrong_bio = [0xffu8; 32]; // wrong biometric → wrong PIN → C_Login rejected
        let result = ctx.create_registration_session(SLOT_VOTER, &voter_id, &wrong_bio);
        assert!(result.is_err(), "wrong biometric hash must not open session");
    }

    #[test]
    #[ignore]
    fn integration_voting_session_opens_for_existing_voter() {
        let ctx = HsmContext::from_env().expect("context");
        let voter_id = [0x01u8; 32];
        let bio_hash = [0xabu8; 32];
        let session = ctx
            .open_voting_session(SLOT_VOTER, &voter_id, &bio_hash)
            .expect("voting session must open for a registered voter");
        // Voting sessions only unwrap existing keys — no MSK generation here.
        session.logout().expect("logout");
    }

    #[test]
    #[ignore]
    fn integration_generate_wrap_key_and_msk_roundtrip() {
        let ctx = HsmContext::from_env().expect("context");
        let session = ctx.open_session(SLOT_VOTER, "1234").expect("session");

        let kwrap = session
            .require_by_label(LABEL_KWRAP)
            .expect("K_wrap must exist (run key ceremony first)");

        let msk = session.generate_voter_msk().expect("generate MSK");
        let blob = session.wrap_key(kwrap, msk).expect("wrap");
        assert!(!blob.is_empty());

        let _unwrapped = session.unwrap_key(kwrap, &blob).expect("unwrap");
        session.logout().expect("logout");
    }

    #[test]
    #[ignore]
    fn integration_hmac_sign_verify_roundtrip() {
        let ctx = HsmContext::from_env().expect("context");
        let session = ctx.open_session(SLOT_ROOT, "1234").expect("session");

        let attest_key = session
            .require_by_label(LABEL_ATTESTATION)
            .expect("attestation key must exist");

        let msg = b"IDV2-v1-attest\x01\x02\x03\x04\x05\x06\x07\x08";
        let mac = session.hmac_sign(attest_key, msg).expect("sign");
        assert_eq!(mac.len(), 32);

        assert!(session.hmac_verify(attest_key, msg, &mac).expect("verify ok"));

        let mut tampered = mac.clone();
        tampered[0] ^= 0xff;
        assert!(!session.hmac_verify(attest_key, msg, &tampered).expect("verify bad"));

        session.logout().expect("logout");
    }
}
