#!/usr/bin/env bash
# Builds the agent binaries for every platform, then the installers this host can build.
#
#   scripts/deploy/build-agent.sh [--version] 1.2.3 [--stack MdmStack] [--profile P] [--region R]
#                                 [--skip-installers] [--dry-run]
#
# Binaries land in agent/bin/, installers in dist/. The installers are built by
# scripts/deploy/package-installers.sh, which reads the collection URL and the
# Entra tenant and client ids from the deployed stack.
#   Windows host: builds the x64 and arm64 MSIs (needs the WiX toolset).
#   macOS host:   builds the amd64 and arm64 pkgs (needs MDM_SIGN_IDENTITY set
#                 to a Developer ID Installer identity).
#   Other hosts:  binaries only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION=""
VERSION_GIVEN=0  # set once a version is passed on the command line
PACKAGE_ARGS=()  # --stack/--profile/--region, passed to package-installers.sh
SKIP_INSTALLERS=0
DRY_RUN=0

# The help text is the header comment, up to the first line of code.
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; VERSION_GIVEN=1; shift 2 ;;
    --stack|--profile|--region) PACKAGE_ARGS+=("$1" "$2"); shift 2 ;;
    --skip-installers) SKIP_INSTALLERS=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    [0-9]*.[0-9]*.[0-9]*) if [[ $VERSION_GIVEN -eq 0 ]]; then VERSION="$1"; VERSION_GIVEN=1; shift; else echo "unknown argument: $1" >&2; usage >&2; exit 2; fi ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "a version is required and must look like 1.2.3 (e.g. ./build-agent.sh 1.0.0)" >&2
  exit 2
fi

# Use the repo's bundled Go toolchain when go is not on PATH.
if ! command -v go >/dev/null && [[ -x "$ROOT/.tools/go/bin/go" || -x "$ROOT/.tools/go/bin/go.exe" ]]; then
  export PATH="$ROOT/.tools/go/bin:$PATH"
fi

cd "$ROOT"
echo "==> Building agent $VERSION for all targets"
if [[ $DRY_RUN -eq 1 ]]; then
  AGENT_VERSION="$VERSION" node scripts/build-agent.mjs --dry-run
else
  AGENT_VERSION="$VERSION" node scripts/build-agent.mjs
fi

if [[ $SKIP_INSTALLERS -eq 1 ]]; then
  echo "==> Skipping installers"
  exit 0
fi

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Darwin)
    # dotnet installs global tools here, which a Git Bash PATH often lacks.
    [[ -d "$HOME/.dotnet/tools" ]] && export PATH="$PATH:$HOME/.dotnet/tools"
    if [[ "$(uname -s)" != Darwin && $DRY_RUN -eq 0 ]] && ! command -v wix >/dev/null; then
      echo "the WiX toolset (wix) is not installed; install it with:" >&2
      echo "  dotnet tool install --global wix --version 5.0.2" >&2
      echo "or pass --skip-installers to build the agent binaries only" >&2
      exit 2
    fi
    [[ $DRY_RUN -eq 1 ]] && PACKAGE_ARGS+=(--dry-run)
    scripts/deploy/package-installers.sh "$VERSION" ${PACKAGE_ARGS[@]+"${PACKAGE_ARGS[@]}"}
    ;;
  *)
    echo "==> No installer toolchain on $(uname -s): binaries only."
    echo "    Build the MSIs on Windows and the pkgs on macOS, then publish from either."
    ;;
esac

echo "==> Done. Installers in dist/:"
ls -1 dist/OfficeHQ-MDM-"$VERSION"-* 2>/dev/null || echo "    (none built)"
