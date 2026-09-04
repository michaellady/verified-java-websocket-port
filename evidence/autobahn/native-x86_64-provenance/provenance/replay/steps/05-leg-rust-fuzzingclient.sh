#!/bin/bash
# Leg R-A: Rust subject in the SERVER role, wstest drives as fuzzingclient.
# Provenance for both processes is captured while they are alive; none of it
# is recoverable afterwards, which is why the capture sits inside the leg.
set -uo pipefail
export PATH=/usr/local/go/bin:/opt/cargo/bin:$PATH
export HOME=/root GOPATH=/root/go
ATTEMPT="us019-prov-20260828T183623Z"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
EV=/opt/vjwp/evidence/autobahn/native-x86_64-provenance
P="$EV/provenance/rust-fuzzingclient"
RUN="$EV/rust/fuzzingclient-run1"
REPORTS="/opt/vjwp/capture/$ATTEMPT/reports-rust-fc"
CONTAINER="${ATTEMPT}-fc-rust"

docker rm -f "$CONTAINER" >/dev/null 2>&1
rm -rf "$REPORTS" "$RUN"
mkdir -p "$P" "$RUN/cases" "$REPORTS"

echo "=== START SUBJECT (Rust, server role) ==="
/opt/vjwp/rust/target/release/ws-testee serve 127.0.0.1:9010 247 \
  > "$RUN/serve.log" 2>&1 &
TESTEE_PID=$!
for i in $(seq 1 60); do
  grep -q "listening" "$RUN/serve.log" 2>/dev/null && break
  sleep 1
done
head -1 "$RUN/serve.log"
echo "TESTEE_PID=$TESTEE_PID"

echo "=== CAPTURE SUBJECT PROCESS PROVENANCE (while alive) ==="
provcap proc -pid "$TESTEE_PID" -role subject-under-test-rust-server \
  -label "$ATTEMPT/rust-fuzzingclient" -out "$P/subject-process.json"
echo "PROVCAP_SUBJECT_EXIT=$?"

echo "=== START HARNESS wstest --mode fuzzingclient (detached, host network) ==="
docker run -d --pull=never --network host --name "$CONTAINER" \
  -v "$EV/config:/config" -v "$REPORTS:/reports" \
  "$IMG" wstest --mode fuzzingclient --spec /config/fuzzingclient-rust.json >/dev/null
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ] && break
  sleep 1
done

echo "=== CAPTURE HARNESS CONTAINER PROVENANCE (while running) ==="
provcap container -name "$CONTAINER" -role harness-wstest-fuzzingclient \
  -label "$ATTEMPT/rust-fuzzingclient" -out "$P/harness-container.json"
echo "PROVCAP_HARNESS_EXIT=$?"

echo "=== AWAIT SWEEP ==="
WSTEST_EXIT=$(docker wait "$CONTAINER")
echo "WSTEST_EXIT=$WSTEST_EXIT"
docker logs "$CONTAINER" > "$RUN/wstest.log" 2>&1
docker rm -f "$CONTAINER" >/dev/null 2>&1

wait $TESTEE_PID
TESTEE_EXIT=$?
echo "TESTEE_EXIT=$TESTEE_EXIT"
tail -3 "$RUN/serve.log"

echo "=== COLLECT REPORTS ==="
if [ ! -f "$REPORTS/index.json" ]; then
  echo "::error:: no index.json produced"; ls -la "$REPORTS/"; exit 1
fi
cp "$REPORTS/index.json" "$RUN/index.json"
for f in "$REPORTS"/*case*.json; do cp "$f" "$RUN/cases/"; done
echo "case files: $(ls "$RUN/cases"/*.json 2>/dev/null | wc -l)"
echo "LEG_RUST_FUZZINGCLIENT_DONE wstest_exit=$WSTEST_EXIT testee_exit=$TESTEE_EXIT"
