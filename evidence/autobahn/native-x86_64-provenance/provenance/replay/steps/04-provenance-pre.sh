#!/bin/bash
# Provenance that must exist BEFORE any sweep runs: the image digest the run
# will be invoked BY, and the source identity of the tree under test.
set -euo pipefail
export PATH=/usr/local/go/bin:$PATH
ATTEMPT="us019-prov-20260828T183623Z"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
COMMIT="518b77aa3ecdc180c832a0d988adf498d687e1b8"
BRANCH="claude/us019-native-run"
PAYLOAD_SHA="967caaefdc6fe655057dfebe799f085f50a04c94b6b54b428eb54eccc2736aac"
EV=/opt/vjwp/evidence/autobahn/native-x86_64-provenance
P="$EV/provenance"
mkdir -p "$P"

echo "=== IMAGE DIGEST PROVENANCE (invoked BY manifest digest, not by tag) ==="
provcap image -image "$IMG" -out "$P/image-digest.json"
echo "PROVCAP_IMAGE_EXIT=$?"
grep -E '"invoked_by"|"invoked_by_form"|"bound"|"requested_digest"' "$P/image-digest.json"

echo "=== SOURCE IDENTITY PROVENANCE ==="
provcap source \
  -commit "$COMMIT" -branch "$BRANCH" \
  -payload-sha256 "$PAYLOAD_SHA" -payload-path /tmp/vjwp-payload.tgz \
  -root /opt/vjwp \
  -files "autobahn/case-manifest.json,autobahn/fuzzingclient.json,autobahn/fuzzingserver.json,rust/target/release/ws-testee,bin/autobahnsuitectl,build/java/autobahn-endpoint.jar,build/java/Java-WebSocket-1.6.0.jar,build/java/slf4j-api-2.0.13.jar,autobahn-endpoint/src/main/java/AutobahnEndpoint.java" \
  -out "$P/source-identity.json"
echo "PROVCAP_SOURCE_EXIT=$?"
grep -E '"commit_sha"|"payload_digest_matches"' -A2 "$P/source-identity.json" | head -20

echo "=== HOST-SIDE RESOURCE CONTEXT (the envelope every leg inherits) ==="
{
  echo "--- host rlimits of this SSM shell ---"
  cat /proc/self/limits
  echo "--- host cgroup v2 controllers ---"
  cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "(absent)"
  echo "--- host memory ---"
  head -3 /proc/meminfo
  echo "--- nproc ---"
  nproc
} > "$P/host-resource-context.txt" 2>&1
cat "$P/host-resource-context.txt"

echo "PROVENANCE_PRE_OK"
