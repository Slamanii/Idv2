//! Key ceremony — one-time bootstrap of HSM token objects.
//!
//! Generates the three long-lived secrets the system needs:
//!
//!   1. **K_wrap**         — AES-256 key-wrapping key.  Wraps voter MSKs.
//!   2. **Attestation key** — HMAC-SHA256 key.  Signs commitment ‖ election_id.
//!   3. **Ballot-sign key** — Ed25519 keypair.  Signs nullifier ‖ commitment
//!                            at vote-cast time; public key goes on-chain in
//!                            `ElectionAccount.aggregation_pubkey`.
//!
//! All three are stored as token objects (persistent across sessions) in the
//! HSM slot specified by `--slot`.
//!
//! Run once per election deployment:
//!
//!   source scripts/setup-softhsm.sh
//!   cargo run -p enclave --bin key_ceremony -- --slot 0 --pin 1234
//!
//! Copy the printed Ed25519 pubkey into the `create_election` instruction.

use anyhow::Context;
use clap::Parser;
use enclave::hsm::{HsmContext, LABEL_ATTESTATION, LABEL_ED25519_SIGN, LABEL_KWRAP};

#[derive(Parser)]
#[command(about = "Bootstrap HSM token objects for idv2")]
struct Args {
    /// PKCS#11 slot index (0-based, from softhsm2-util --show-slots).
    #[arg(long, default_value_t = 0)]
    slot: usize,

    /// Plaintext operator PIN for the target slot.
    #[arg(long, default_value = "1234")]
    pin: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let ctx = HsmContext::from_env().context("failed to load PKCS#11 library — is SOFTHSM2_LIB set?")?;
    let session = ctx
        .open_session(args.slot, &args.pin)
        .context("C_Login failed — check slot index and PIN")?;

    println!("=== idv2 Key Ceremony ===");
    println!("slot  : {}", args.slot);
    println!();

    // ── K_wrap ────────────────────────────────────────────────────────────────
    if session.find_by_label(LABEL_KWRAP)?.is_some() {
        println!("[skip] K_wrap already exists ({})", label_str(LABEL_KWRAP));
    } else {
        session
            .generate_wrap_key(LABEL_KWRAP)
            .context("generate K_wrap failed")?;
        println!("[done] K_wrap generated  ({})", label_str(LABEL_KWRAP));
    }

    // ── Attestation key ───────────────────────────────────────────────────────
    if session.find_by_label(LABEL_ATTESTATION)?.is_some() {
        println!("[skip] attestation key already exists ({})", label_str(LABEL_ATTESTATION));
    } else {
        session
            .generate_attestation_key(LABEL_ATTESTATION)
            .context("generate attestation key failed")?;
        println!("[done] attestation key generated  ({})", label_str(LABEL_ATTESTATION));
    }

    // ── Ed25519 ballot-signing keypair ────────────────────────────────────────
    let ed_pubkey = if let Some(_) = session.find_pub_by_label(LABEL_ED25519_SIGN)? {
        println!("[skip] Ed25519 ballot-signing key already exists ({})", label_str(LABEL_ED25519_SIGN));
        let pub_handle = session
            .require_pub_by_label(LABEL_ED25519_SIGN)
            .context("failed to locate existing Ed25519 public key")?;
        session
            .get_ed25519_pubkey(pub_handle)
            .context("failed to read Ed25519 public key")?
    } else {
        let (pub_handle, _priv_handle) = session
            .generate_ed25519_keypair(LABEL_ED25519_SIGN)
            .context("generate Ed25519 keypair failed")?;
        println!("[done] Ed25519 ballot-signing key generated  ({})", label_str(LABEL_ED25519_SIGN));
        session
            .get_ed25519_pubkey(pub_handle)
            .context("failed to read new Ed25519 public key")?
    };

    println!();
    println!("=== Ed25519 public key ===");
    println!("{}", hex_encode(&ed_pubkey));
    println!();
    println!("Store this pubkey in ElectionAccount.aggregation_pubkey when calling");
    println!("election_registry::create_election.");

    session.logout()?;
    Ok(())
}

fn label_str(label: &[u8]) -> &str {
    std::str::from_utf8(label).unwrap_or("<binary>")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
