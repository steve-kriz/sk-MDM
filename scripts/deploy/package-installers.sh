#!/usr/bin/env bash
# Builds the installers this host can build, with every baked value read from AWS.
#
#   scripts/deploy/package-installers.sh [--version] 1.2.3 [--platform windows|macos|auto]
#                                        [--arch x64|arm64] [--stack MdmStack]
#                                        [--profile P] [--region R] [--dry-run]
#
# 1. Reads the CollectionUrl output of the stack (aws cloudformation describe-stacks).
# 2. Reads tenantId and clientId from <CollectionUrl>/api/v1/agent-auth/config.
# 3. Builds with those values baked in:
#      windows (Git Bash): the x64 and arm64 MSIs (needs the WiX toolset)
#      macos:              the amd64 and arm64 pkgs (needs MDM_SIGN_IDENTITY)
#    --platform auto (the default) picks by host; --arch builds one architecture.
#
# Installers land in dist/; publish them with scripts/deploy/publish-installers.sh.
# --dry-run does the two reads, prints the values and the build commands, and
# builds nothing. Exits 1 when the stack or the config route cannot be read.
# The agent binaries must already be in agent/bin/ (scripts/deploy/build-agent.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The help text is the header comment, up to the first line of code.
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
  esac
done

command -v aws >/dev/null || { echo "the AWS CLI is required on PATH" >&2; exit 2; }
command -v node >/dev/null || { echo "Node.js is required on PATH" >&2; exit 2; }

# dotnet installs global tools (wix) here, which a Git Bash PATH often lacks.
if [[ -d "$HOME/.dotnet/tools" ]]; then
  export PATH="$PATH:$HOME/.dotnet/tools"
fi

cd "$ROOT"
exec node scripts/package-installers.mjs "$@"
