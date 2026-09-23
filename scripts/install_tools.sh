#!/usr/bin/env bash
# Install the pinned policy toolchain into a directory (default: ./.tools/bin).
# Every artifact is verified against a SHA256 pinned in this file, not against
# a checksum fetched from the same place as the artifact.
#
# Usage: scripts/install_tools.sh [install-dir]
# Linux x86_64 only (CI runners). On macOS use Homebrew with the same versions.
set -euo pipefail

log() { printf '%s install-tools: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

readonly OPA_VERSION="1.20.2"
readonly OPA_SHA256="69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f"
readonly CONFTEST_VERSION="0.70.1"
readonly CONFTEST_SHA256="613d124b8f6c1f3cee890491f7ab19114cca5a2102ca47cb2e6c35b4c23f9c8a"
readonly GATOR_VERSION="3.23.1"
readonly GATOR_SHA256="c268d7b809c9fe59a110ab0bf7c296ab00b0b6c894c209cd15e94194590291bb"
readonly TERRAFORM_VERSION="1.16.4"
readonly TERRAFORM_SHA256="dc94af0eef1147718ad7c8daea792ed199e3e0492eec180d0adafa2a65a879df"

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || die "only Linux x86_64 is supported"
for bin in curl sha256sum tar unzip; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin is required"
done

INSTALL_DIR="${1:-$PWD/.tools/bin}"
mkdir -p "$INSTALL_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { # url sha256 dest
  local url="$1" sha="$2" dest="$3"
  log "downloading $url"
  curl -fsSL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 -o "$dest" "$url"
  echo "${sha}  ${dest}" | sha256sum --check --quiet - || die "checksum mismatch for $url"
}

fetch "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
  "$OPA_SHA256" "$TMP/opa"
install -m 0755 "$TMP/opa" "$INSTALL_DIR/opa"

fetch "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" \
  "$CONFTEST_SHA256" "$TMP/conftest.tar.gz"
tar -xzf "$TMP/conftest.tar.gz" -C "$TMP" conftest
install -m 0755 "$TMP/conftest" "$INSTALL_DIR/conftest"

fetch "https://github.com/open-policy-agent/gatekeeper/releases/download/v${GATOR_VERSION}/gator-v${GATOR_VERSION}-linux-amd64.tar.gz" \
  "$GATOR_SHA256" "$TMP/gator.tar.gz"
tar -xzf "$TMP/gator.tar.gz" -C "$TMP" gator
install -m 0755 "$TMP/gator" "$INSTALL_DIR/gator"

fetch "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
  "$TERRAFORM_SHA256" "$TMP/terraform.zip"
unzip -q -o "$TMP/terraform.zip" terraform -d "$TMP"
install -m 0755 "$TMP/terraform" "$INSTALL_DIR/terraform"

"$INSTALL_DIR/opa" version | head -1 >&2
"$INSTALL_DIR/conftest" --version | head -1 >&2
"$INSTALL_DIR/gator" --version >&2
"$INSTALL_DIR/terraform" version | head -1 >&2
log "installed to $INSTALL_DIR"
