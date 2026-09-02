#!/bin/bash
# Leg J-A: pinned Java-WebSocket 1.6.0 in the SERVER role, wstest drives as
# fuzzingclient. Same host, same image digest, same 247-case manifest as the
# Rust legs; that is what makes the comparison load-bearing.
set -uo pipefail
export PATH=/usr/local/go/bin:$PATH
export HOME=/root
ATTEMPT="us019-prov-20260828T183623Z"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
EV=/opt/vjwp/evidence/autobahn/native-x86_64-provenance
P="$EV/provenance/java-fuzzingclient"
RUN="$EV/java/fuzzingclient-run1"
REPORTS="/opt/vjwp/capture/$ATTEMPT/reports-java-fc"
CONTAINER="${ATTEMPT}-fc-java"
JB=/opt/vjwp/build/java
ADAPTER_DIGEST=$(cat "$JB/adapter-digest")
CP="$JB/autobahn-endpoint.jar:$JB/Java-WebSocket-1.6.0.jar:$JB/slf4j-api-2.0.13.jar"

docker rm -f "$CONTAINER" >/dev/null 2>&1
rm -rf "$REPORTS" "$RUN"
mkdir -p "$P" "$RUN/cases" "$REPORTS"

echo "=== START JAVA BASELINE (server role, port 9011) ==="
java -cp "$CP" AutobahnEndpoint server \
  --adapter "$JB/autobahn-endpoint.jar" --adapter-digest "$ADAPTER_DIGEST" \
  --runtime "$JB/Java-WebSocket-1.6.0.jar" --support "$JB/slf4j-api-2.0.13.jar" \
  --bind 127.0.0.1 --port 9011 --max-seconds 1800 > "$RUN/serve.log" 2>&1 &
JAVA_PID=$!
READY=0
for i in $(seq 1 60); do
  grep -q "SERVER_READY" "$RUN/serve.log" 2>/dev/null && { READY=1; break; }
  kill -0 "$JAVA_PID" 2>/dev/null || break
  sleep 1
done
echo "JAVA_SERVER_READY=$READY"
cat "$RUN/serve.log"
if [ "$READY" -ne 1 ]; then
  echo "::error:: java baseline server never became ready"
  kill "$JAVA_PID" 2>/dev/null; exit 1
fi
echo "JAVA_PID=$JAVA_PID"

echo "=== CAPTURE JAVA BASELINE PROCESS PROVENANCE (while alive) ==="
provcap proc -pid "$JAVA_PID" -role java-baseline-server \
  -label "$ATTEMPT/java-fuzzingclient" -out "$P/subject-process.json"
echo "PROVCAP_SUBJECT_EXIT=$?"

echo "=== START HARNESS wstest --mode fuzzingclient (detached, host network) ==="
docker run -d --pull=never --network host --name "$CONTAINER" \
  -v "$EV/config:/config" -v "$REPORTS:/reports" \
  "$IMG" wstest --mode fuzzingclient --spec /config/fuzzingclient-java.json >/dev/null
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ] && break
  sleep 1
done

echo "=== CAPTURE HARNESS CONTAINER PROVENANCE (while running) ==="
provcap container -name "$CONTAINER" -role harness-wstest-fuzzingclient \
  -label "$ATTEMPT/java-fuzzingclient" -out "$P/harness-container.json"
echo "PROVCAP_HARNESS_EXIT=$?"

echo "=== AWAIT SWEEP ==="
WSTEST_EXIT=$(docker wait "$CONTAINER")
echo "WSTEST_EXIT=$WSTEST_EXIT"
docker logs "$CONTAINER" > "$RUN/wstest.log" 2>&1
docker rm -f "$CONTAINER" >/dev/null 2>&1

kill "$JAVA_PID" 2>/dev/null
wait $JAVA_PID
JAVA_EXIT=$?
echo "JAVA_EXIT=$JAVA_EXIT (terminated by this script after the sweep completed)"
tail -3 "$RUN/serve.log"

echo "=== COLLECT REPORTS ==="
if [ ! -f "$REPORTS/index.json" ]; then
  echo "::error:: no index.json produced"; ls -la "$REPORTS/"; exit 1
fi
cp "$REPORTS/index.json" "$RUN/index.json"
for f in "$REPORTS"/*case*.json; do cp "$f" "$RUN/cases/"; done
echo "case files: $(ls "$RUN/cases"/*.json 2>/dev/null | wc -l)"
echo "LEG_JAVA_FUZZINGCLIENT_DONE wstest_exit=$WSTEST_EXIT"
