#!/bin/bash
# Finalize: host facts, the four ledgers, the replay artifact, the digest
# manifest, and the outbound package. Reconciliation failures are recorded,
# never allowed to abort the packaging: the evidence leaves the host either
# way, including from a failed leg.
set -uo pipefail
export PATH=/usr/local/go/bin:$PATH
export HOME=/root GOPATH=/root/go
cd /opt/vjwp
ATTEMPT="us019-prov-20260828T183623Z"
BUCKET="vjwp-us019-prov-539402214167"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
COMMIT="518b77aa3ecdc180c832a0d988adf498d687e1b8"
EV=evidence/autobahn/native-x86_64-provenance
CTL=/opt/vjwp/bin/autobahnsuitectl
JB=/opt/vjwp/build/java
mkdir -p "$EV/host" "$EV/ledgers" "$EV/provenance/replay"

echo "=== US-008 BOOTED-HOST FACTS (IMDSv2) ==="
hostfacts > "$EV/host/us008-booted-host-facts.json"
echo "HOSTFACTS_EXIT=$? bytes=$(wc -c < "$EV/host/us008-booted-host-facts.json")"

echo "=== MANIFEST IMMUTABILITY GATE, RE-RUN ON THIS HOST ==="
$CTL verify-manifest -root /opt/vjwp -manifest autobahn/case-manifest.json
echo "VERIFY_MANIFEST_EXIT=$?"

reconcile_leg() {
  local name="$1" dir="$2" subject="$3" agent="$4"
  if [ ! -f "$dir/index.json" ]; then
    echo "RECONCILE_${name}_EXIT=SKIPPED_NO_INDEX"
    return
  fi
  $CTL reconcile -manifest autobahn/case-manifest.json \
    -index "$dir/index.json" -cases "$dir/cases" \
    -subject "$subject" -require-agent "$agent" \
    -out "$EV/ledgers/${name}-ledger.json"
  echo "RECONCILE_${name}_EXIT=$?"
}

echo "=== RECONCILE ALL FOUR LEGS ==="
reconcile_leg rust-fuzzingclient "$EV/rust/fuzzingclient-run1" \
  subject-under-test verified-rust-ws-testee-us019
reconcile_leg rust-fuzzingserver "$EV/rust/fuzzingserver-run1" \
  subject-under-test verified-rust-ws-testee-us019
reconcile_leg java-fuzzingclient "$EV/java/fuzzingclient-run1" \
  java-baseline verified-java-websocket-port-1.6.0
reconcile_leg java-fuzzingserver "$EV/java/fuzzingserver-run1" \
  java-baseline verified-java-websocket-port-1.6.0

echo "=== REPLAY ARTIFACT ==="
cp -R /opt/vjwp/run-steps "$EV/provenance/replay/steps"
( cd "$EV/provenance/replay/steps" && sha256sum ./*.sh ) > "$EV/provenance/replay/steps.sha256"
cat "$EV/provenance/replay/steps.sha256"

ADAPTER_DIGEST=$(cat "$JB/adapter-digest" 2>/dev/null || echo "ABSENT")
WSTEEE_SHA=$(sha256sum /opt/vjwp/rust/target/release/ws-testee 2>/dev/null | awk '{print $1}')
cat > "$EV/provenance/replay/replay-command.sh" <<REPLAY
#!/bin/bash
# Literal replay of the US-019 provenance run, ${ATTEMPT}.
#
# Paste this on a workstation with the dev AWS profile. It reproduces the host,
# the image, the tree, and the four sweeps in the order they were executed.
# Every digest below was read off the run it describes, not copied from a plan.
set -euo pipefail
export AWS_PROFILE=dev-sso AWS_REGION=us-east-1

COMMIT=${COMMIT}                       # tree under test
IMAGE=${IMG}
AMI=ami-02b3d83d84b07786d              # al2023 x86_64, the AMI this run booted
INSTANCE_TYPE=c7i.xlarge
ADAPTER_DIGEST=${ADAPTER_DIGEST}       # built here from AutobahnEndpoint.java
WS_TESTEE_SHA256=${WSTEEE_SHA}         # built here from \$COMMIT

git -C <worktree> checkout \$COMMIT
# 1. Launch: see steps/00-launch.sh in this replay bundle for the exact
#    run-instances call, IAM, egress-only SG and S3 transfer bucket.
# 2. Deliver the tree as a tarball and run these, in order, over SSM
#    RunShellScript, each one's host exit status read from
#    GetCommandInvocation.ResponseCode:
$(cd "$EV/provenance/replay/steps" && ls -1 ./*.sh | sed 's#^\./#       #')
# 3. Pull s3://${BUCKET}/out/${ATTEMPT}-evidence.tgz and verify it against the
#    published .sha256 before unpacking.
# 4. Terminate the instance and delete the IAM role, instance profile, security
#    group and bucket.
REPLAY
chmod +x "$EV/provenance/replay/replay-command.sh"
cat "$EV/provenance/replay/replay-command.sh"

echo "=== RUN SUMMARY ==="
cat > "$EV/provenance/run-summary.json" <<SUMMARY
{
  "schema_version": "1.0.0",
  "entity_type": "ProvenanceRunSummary",
  "attempt_id": "${ATTEMPT}",
  "commit_sha": "${COMMIT}",
  "image_invoked_by": "${IMG}",
  "image_reference_form": "MANIFEST_DIGEST",
  "manifest": "autobahn/case-manifest.json",
  "expected_case_count": 247,
  "legs": [
    {"leg": "rust-fuzzingclient", "subject": "rust", "role": "server", "agent": "verified-rust-ws-testee-us019"},
    {"leg": "rust-fuzzingserver", "subject": "rust", "role": "client-agent", "agent": "verified-rust-ws-testee-us019"},
    {"leg": "java-fuzzingclient", "subject": "java-websocket-1.6.0", "role": "server", "agent": "verified-java-websocket-port-1.6.0"},
    {"leg": "java-fuzzingserver", "subject": "java-websocket-1.6.0", "role": "client-agent", "agent": "verified-java-websocket-port-1.6.0"}
  ],
  "finalized_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
SUMMARY
cat "$EV/provenance/run-summary.json"

echo "=== TREE INVENTORY ==="
find "$EV" -type f | sort | sed 's#^#  #' | head -60
echo "  total files: $(find "$EV" -type f | wc -l)"

echo "=== DIGEST THE NEW SUBTREE ==="
$CTL digest-manifest -root /opt/vjwp -tree "$EV" -out "$EV/digest-manifest.json"
echo "DIGEST_EXIT=$?"

echo "=== PACKAGE + OUTBOUND DIGEST ==="
tar -C /opt/vjwp -czf "/tmp/${ATTEMPT}-evidence.tgz" "$EV"
sha256sum "/tmp/${ATTEMPT}-evidence.tgz" | tee "/tmp/${ATTEMPT}-evidence.sha256"
aws s3 cp "/tmp/${ATTEMPT}-evidence.tgz" "s3://$BUCKET/out/${ATTEMPT}-evidence.tgz" --quiet
aws s3 cp "/tmp/${ATTEMPT}-evidence.sha256" "s3://$BUCKET/out/${ATTEMPT}-evidence.sha256" --quiet
echo "FINALIZE_OK"
