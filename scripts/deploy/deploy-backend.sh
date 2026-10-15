#!/usr/bin/env bash
# Builds the backend and deploys the MdmStack CDK stack.
#
#   scripts/deploy/deploy-backend.sh [--profile P] [--region R] [--yes] [-- <extra cdk deploy args>]
#
# The ACM certificate ARN (us-east-1) is read at synth from the MDM_CERTIFICATE_ARN
# key of the Secrets Manager secret prod/sk-mdm, so the AWS identity in use needs
# secretsmanager:GetSecretValue on it as well as deploy permissions.
# Optional environment (each overrides the default):
#   MDM_CERTIFICATE_ARN  Overrides the certificate ARN in the secret.
#   MDM_HOSTED_ZONE_ID   Route 53 zone for officehq.cc; DNS records are created when set.
#   MDM_DOMAIN_NAME      Defaults to mdm.officehq.cc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STACK_NAME="MdmStack"
APPROVAL="broadening"
CDK_EXTRA=()

# The help text is the header comment, up to the first line of code.
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) export AWS_PROFILE="$2"; shift 2 ;;
    --region) export AWS_REGION="$2" AWS_DEFAULT_REGION="$2"; shift 2 ;;
    --yes) APPROVAL="never"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; CDK_EXTRA=("$@"); break ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# An override from the environment is checked against the rule MdmStack enforces
# at synth (CloudFront only accepts us-east-1 certificates), so it fails before
# the build. A value from the secret is checked at synth.
if [[ -n "${MDM_CERTIFICATE_ARN:-}" ]]; then
  if [[ ! "$MDM_CERTIFICATE_ARN" =~ ^arn:aws:acm:us-east-1:[0-9]{12}:certificate/[A-Za-z0-9-]+$ ]]; then
    echo "MDM_CERTIFICATE_ARN must be an ACM certificate in us-east-1 (CloudFront requirement), got:" >&2
    echo "  $MDM_CERTIFICATE_ARN" >&2
    exit 2
  fi
  export MDM_CERTIFICATE_ARN
fi
command -v aws >/dev/null || { echo "the AWS CLI is required on PATH" >&2; exit 2; }

echo "==> Checking AWS credentials"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGION="${AWS_REGION:-$(aws configure get region || true)}"
[[ -n "$REGION" ]] || { echo "no AWS region: pass --region or configure one" >&2; exit 2; }
export CDK_DEFAULT_ACCOUNT="$ACCOUNT" CDK_DEFAULT_REGION="$REGION"
echo "    account $ACCOUNT, region $REGION"

cd "$ROOT"
echo "==> Installing dependencies"
npm ci

echo "==> Building backend and Lambda bundle"
npm run build

cd "$ROOT/backend"
if ! aws cloudformation describe-stacks --stack-name CDKToolkit >/dev/null 2>&1; then
  echo "==> Bootstrapping CDK in $ACCOUNT/$REGION"
  npx cdk bootstrap "aws://$ACCOUNT/$REGION"
fi

echo "==> Deploying $STACK_NAME"
npx cdk deploy "$STACK_NAME" --require-approval "$APPROVAL" ${CDK_EXTRA[@]+"${CDK_EXTRA[@]}"}

echo "==> Stack outputs"
aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
