#!/bin/bash
# US-019 provenance re-run: teardown, driven by the resource ledger rather than
# by memory of what was created. Safe to run repeatedly and safe to run after a
# failure; every step tolerates an already-absent resource and the destruction
# proofs at the end are read independently rather than inferred from the
# terminate call's own return.
set -uo pipefail
export AWS_PROFILE=dev-sso
export AWS_REGION=us-east-1

W=/Users/mikelady/hq/workspace/worktrees/vjwp-claude-native-run/.runlog/us019-rerun
LEDGER="$W/out/resources.env"
[ -f "$LEDGER" ] || { echo "::error:: no resource ledger at $LEDGER"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$LEDGER"; set +a
echo "TEARDOWN_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat "$LEDGER"

if [ -n "${INSTANCE_ID:-}" ]; then
  echo "=== TERMINATE $INSTANCE_ID ==="
  echo "TERMINATE_REQUESTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --output json
  aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
  echo "WAIT_TERMINATED_EXIT=$?"
  aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text
  echo "TERMINATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

echo "=== DESTRUCTION PROOFS (read independently of the terminate call) ==="
if [ -n "${VOLUME_ID:-}" ]; then
  aws ec2 describe-volumes --volume-ids "$VOLUME_ID" >/dev/null 2>&1
  echo "PROOF_VOLUME_GONE_EXIT=$? (nonzero means the volume no longer exists)"
fi
if [ -n "${ENI_ID:-}" ]; then
  aws ec2 describe-network-interfaces --network-interface-ids "$ENI_ID" >/dev/null 2>&1
  echo "PROOF_ENI_GONE_EXIT=$? (nonzero means the interface no longer exists)"
fi

echo "=== SCAFFOLDING ==="
if [ -n "${BUCKET:-}" ]; then
  aws s3 rm "s3://$BUCKET" --recursive --quiet
  aws s3api delete-bucket --bucket "$BUCKET"
  echo "DELETE_BUCKET_EXIT=$?"
fi
if [ -n "${SGID:-}" ]; then
  aws ec2 delete-security-group --group-id "$SGID"
  echo "DELETE_SG_EXIT=$?"
fi
if [ -n "${INSTANCE_PROFILE:-}" ]; then
  aws iam remove-role-from-instance-profile \
    --instance-profile-name "$INSTANCE_PROFILE" --role-name "$ROLE"
  aws iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE"
  echo "DELETE_INSTANCE_PROFILE_EXIT=$?"
fi
if [ -n "${ROLE:-}" ]; then
  aws iam delete-role-policy --role-name "$ROLE" --policy-name transfer-bucket
  aws iam detach-role-policy --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  aws iam delete-role --role-name "$ROLE"
  echo "DELETE_ROLE_EXIT=$?"
fi

echo "=== FINAL SWEEP: anything still alive under this project's tags ==="
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=vjwp" \
    "Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text
echo "(no rows above means nothing is left running)"
aws ec2 describe-volumes --filters "Name=tag:Project,Values=vjwp" \
  --query 'Volumes[].[VolumeId,State]' --output text
echo "(no rows above means no volumes are left)"
aws iam list-roles --query 'Roles[?starts_with(RoleName, `vjwp`)].RoleName' --output text
echo "(no rows above means no roles are left)"
echo "TEARDOWN_FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
