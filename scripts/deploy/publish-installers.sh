#!/usr/bin/env bash
# Uploads the built installers in dist/ to the stack's installer bucket.
#
#   scripts/deploy/publish-installers.sh [--version] 1.2.3 [--bucket B] [--stack MdmStack]
#                                        [--profile P] [--region R] [--dry-run]
#
# Without --bucket, the bucket name is read from the stack's InstallerBucketName
# output. Installers missing from dist/ are skipped, so Windows and macOS
# installers can be published from different machines.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="1.0.0"
VERSION_GIVEN=0  # set once a version is passed on the command line
BUCKET="mdmstack-installerbucket425dca4d-kbhk7dr3otxl"
STACK_NAME="MdmStack"
DRY_RUN=()

# The help text is the header comment, up to the first line of code.
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; VERSION_GIVEN=1; shift 2 ;;
    --bucket) BUCKET="$2"; shift 2 ;;
    --stack) STACK_NAME="$2"; shift 2 ;;
    --profile) export AWS_PROFILE="$2"; shift 2 ;;
    --region) export AWS_REGION="$2" AWS_DEFAULT_REGION="$2"; shift 2 ;;
    --dry-run) DRY_RUN=(--dry-run); shift ;;
    -h|--help) usage; exit 0 ;;
    [0-9]*.[0-9]*.[0-9]*) if [[ $VERSION_GIVEN -eq 0 ]]; then VERSION="$1"; VERSION_GIVEN=1; shift; else echo "unknown argument: $1" >&2; usage >&2; exit 2; fi ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "a version is required and must look like 1.2.3 (e.g. ./publish-installers.sh 1.0.0)" >&2
  exit 2
fi
command -v aws >/dev/null || { echo "the AWS CLI is required on PATH" >&2; exit 2; }

if [[ -z "$BUCKET" ]]; then
  echo "==> Reading InstallerBucketName from stack $STACK_NAME"
  BUCKET="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='InstallerBucketName'].OutputValue" --output text)"
  if [[ -z "$BUCKET" || "$BUCKET" == "None" ]]; then
    echo "stack $STACK_NAME has no InstallerBucketName output; deploy the backend first or pass --bucket" >&2
    exit 1
  fi
fi

echo "==> Publishing installers $VERSION to s3://$BUCKET"
cd "$ROOT"
node scripts/publish-installers.mjs --bucket "$BUCKET" --version "$VERSION" ${DRY_RUN[@]+"${DRY_RUN[@]}"}
