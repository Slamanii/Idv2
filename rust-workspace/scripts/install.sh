#!/usr/bin/env bash
# idv2 — one-shot prerequisite installer.
#
# Installs, in order:
#   1. Rustup stable toolchain (if missing)
#   2. Solana CLI (agave / stable 1.18+) via official installer
#   3. cargo-build-sbf (comes with Solana CLI; sanity-check)
#   4. SoftHSM2 + opensc (for PKCS#11 development on Linux/macOS)
#
# Idempotent: re-running only updates what is already present.

set -euo pipefail

log() { printf "\033[1;34m[idv2-install]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[idv2-install]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[idv2-install]\033[0m %s\n" "$*" >&2; }



# ---- 2. Solana CLI -------------------------------------------------------
SOLANA_VERSION="${SOLANA_VERSION:-stable}"
if ! command -v solana >/dev/null 2>&1; then
  log "Installing Solana CLI ($SOLANA_VERSION)…"
  sh -c "$(curl -sSfL https://release.anza.xyz/$SOLANA_VERSION/install)"
  export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
  warn "Add this to your shell profile:"
  warn '  export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"'
else
  log "Solana CLI present: $(solana --version)"
fi

# ---- 3. cargo-build-sbf -------------------------------------------------
if ! command -v cargo-build-sbf >/dev/null 2>&1; then
  err "cargo-build-sbf not on PATH. Check that Solana CLI shimmed correctly."
  exit 1
fi
log "cargo-build-sbf: $(cargo-build-sbf --version 2>&1 | head -1)"

# ---- 4. SoftHSM2 + OpenSC (PKCS#11 dev) ---------------------------------
install_softhsm() {
  case "$(uname -s)" in
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y softhsm2 opensc libssl-dev pkg-config
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y softhsm opensc openssl-devel pkgconf-pkg-config
      else
        warn "Unknown Linux distro — install softhsm2 + opensc manually."
      fi
      ;;
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        brew install softhsm opensc
      else
        warn "Install Homebrew first, then: brew install softhsm opensc"
      fi
      ;;
    *)
      warn "Unsupported OS; install SoftHSM2 manually."
      ;;
  esac
}

if ! command -v softhsm2-util >/dev/null 2>&1; then
  log "Installing SoftHSM2 + OpenSC…"
  install_softhsm
else
  log "SoftHSM2 present: $(softhsm2-util --version 2>&1 | head -1)"
fi

log "Done. Next:  ./scripts/keygen.sh && ./scripts/airdrop.sh"
