#!/usr/bin/env bash
# Install pinned, checksum-verified CLIs (gitleaks, syft, trivy, actionlint).
#
#   scripts/install-tools.sh gitleaks syft trivy actionlint
#
# Why not "curl | sh"?  Because a security pipeline that blindly executes
# a remote installer is itself a supply-chain risk.  Versions AND sha256
# digests are pinned here; bumping a tool is a reviewed one-line diff.
set -euo pipefail

BIN_DIR="${TOOLS_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

GITLEAKS_VERSION="8.30.1"
GITLEAKS_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
SYFT_VERSION="1.55.0"
SYFT_SHA256="bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d"
TRIVY_VERSION="0.76.0"
TRIVY_SHA256="e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7"
ACTIONLINT_VERSION="1.7.12"
ACTIONLINT_SHA256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"

install_tarball() { # name url sha256 binary-name-in-tarball
  local name=$1 url=$2 sha=$3 bin=$4 tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  echo ">> installing ${name}"
  curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/pkg.tgz" "$url"
  echo "${sha}  $tmp/pkg.tgz" | sha256sum --check --status \
    || { echo "!! checksum mismatch for ${name} - refusing to install" >&2; exit 1; }
  tar -xzf "$tmp/pkg.tgz" -C "$tmp" --no-same-owner "$bin"
  install -m 0755 "$tmp/$bin" "$BIN_DIR/$bin"
}

for tool in "$@"; do
  case "$tool" in
    gitleaks) install_tarball gitleaks \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      "$GITLEAKS_SHA256" gitleaks ;;
    syft) install_tarball syft \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
      "$SYFT_SHA256" syft ;;
    trivy) install_tarball trivy \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      "$TRIVY_SHA256" trivy ;;
    actionlint) install_tarball actionlint \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
      "$ACTIONLINT_SHA256" actionlint ;;
    *) echo "unknown tool: $tool (expected gitleaks|syft|trivy|actionlint)" >&2; exit 2 ;;
  esac
done

# make the tools visible to later GitHub Actions steps
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$BIN_DIR" >> "$GITHUB_PATH"; fi
echo "tools in $BIN_DIR"
