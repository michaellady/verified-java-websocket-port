#!/bin/bash
# Leg J-B: pinned Java-WebSocket 1.6.0 in the CLIENT-AGENT role, wstest serves
# as fuzzingserver.
#
# The endpoint pins its Host header to the fixed authority 172.30.242.4:9001
# and refuses any other value, while its URL gate refuses anything but a bare
# loopback origin. Those two constraints are satisfiable together only by
# publishing the port on loopback and sending the fixed authority as a header,
# so the header is preflighted against the live server before the sweep.
set -uo pipefail
export PATH=/usr/local/go/bin:$PATH
export HOME=/root
ATTEMPT="us019-prov-20260828T183623Z"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
EV=/opt/vjwp/evidence/autobahn/native-x86_64-provenance
P="$EV/provenance/java-fuzzingserver"
RUN="$EV/java/fuzzingserver-run1"
REPORTS="/opt/vjwp/capture/$ATTEMPT/reports-java-fs"
CONTAINER="${ATTEMPT}-fs-java"
JB=/opt/vjwp/build/java
ADAPTER_DIGEST=$(cat "$JB/adapter-digest")
CP="$JB/autobahn-endpoint.jar:$JB/Java-WebSocket-1.6.0.jar:$JB/slf4j-api-2.0.13.jar"

docker rm -f "$CONTAINER" >/dev/null 2>&1
rm -rf "$REPORTS" "$RUN"
mkdir -p "$P" "$RUN/cases" "$REPORTS"

echo "=== START HARNESS wstest --mode fuzzingserver ==="
docker run -d -t --pull=never --name "$CONTAINER" -p 127.0.0.1:9001:9001 \
  -v "$EV/config:/config" -v "$REPORTS:/reports" \
  "$IMG" wstest --mode fuzzingserver --spec /config/fuzzingserver-derived.json >/dev/null
READY=0
for i in $(seq 1 90); do
  if docker logs "$CONTAINER" 2>&1 | grep -q "Ok, will run"; then READY=1; break; fi
  sleep 1
done
echo "SERVER_READY=$READY"
if [ "$READY" -ne 1 ]; then
  echo "::error:: server never ready"; docker logs "$CONTAINER" 2>&1 | tail -20
  docker rm -f "$CONTAINER" >/dev/null 2>&1; exit 1
fi
sleep 2

echo "=== CAPTURE HARNESS CONTAINER PROVENANCE (while running) ==="
provcap container -name "$CONTAINER" -role harness-wstest-fuzzingserver \
  -label "$ATTEMPT/java-fuzzingserver" -out "$P/harness-container.json"
echo "PROVCAP_HARNESS_EXIT=$?"

echo "=== HOST-HEADER PREFLIGHT (the fixed authority the endpoint will send) ==="
python3 - <<'PY' | tee /tmp/java-fs-preflight.txt
import socket, base64, os
def probe(host_header):
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET /getCaseCount HTTP/1.1\r\n" + f"Host: {host_header}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           + f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    try:
        s = socket.create_connection(("127.0.0.1", 9001), timeout=10)
        s.sendall(req.encode()); s.settimeout(10)
        data = s.recv(2048)
        print(f"Host {host_header!r} -> bytes={len(data)} {data[:64]!r}")
        return data.startswith(b"HTTP/1.1 101")
    except Exception as e:
        print(f"Host {host_header!r} -> ERROR {type(e).__name__} {e}")
        return False
ok = probe("172.30.242.4:9001")
probe("127.0.0.1:9001")
print("PREFLIGHT_FIXED_AUTHORITY_ACCEPTED=" + ("YES" if ok else "NO"))
PY

echo "=== RUN JAVA BASELINE (client-agent role) ==="
java -cp "$CP" AutobahnEndpoint client \
  --adapter "$JB/autobahn-endpoint.jar" --adapter-digest "$ADAPTER_DIGEST" \
  --runtime "$JB/Java-WebSocket-1.6.0.jar" --support "$JB/slf4j-api-2.0.13.jar" \
  --url ws://127.0.0.1:9001 --host-header 172.30.242.4:9001 --case-count 247 \
  > "$RUN/agent.log" 2>&1 &
JAVA_PID=$!
sleep 3
echo "JAVA_PID=$JAVA_PID"

echo "=== CAPTURE JAVA BASELINE PROCESS PROVENANCE (while alive) ==="
provcap proc -pid "$JAVA_PID" -role java-baseline-client-agent \
  -label "$ATTEMPT/java-fuzzingserver" -out "$P/subject-process.json"
echo "PROVCAP_SUBJECT_EXIT=$?"

wait $JAVA_PID
AGENT_EXIT=$?
echo "AGENT_EXIT=$AGENT_EXIT"
tail -5 "$RUN/agent.log"

# The endpoint aborts the whole walk on the first case that does not connect
# or that exceeds its own timeout, and it is /updateReports that writes the
# index. If the walk aborted, ask the server to emit the reports it already
# holds for this session rather than losing the completed cases.
if [ "$AGENT_EXIT" -ne 0 ]; then
  echo "=== RECOVERY: walk aborted; forcing /updateReports for cases already run ==="
  java -cp "$CP" AutobahnEndpoint client \
    --adapter "$JB/autobahn-endpoint.jar" --adapter-digest "$ADAPTER_DIGEST" \
    --runtime "$JB/Java-WebSocket-1.6.0.jar" --support "$JB/slf4j-api-2.0.13.jar" \
    --url ws://127.0.0.1:9001 --host-header 172.30.242.4:9001 --case-count 1 \
    > "$RUN/agent-recovery.log" 2>&1
  echo "RECOVERY_EXIT=$?"
  tail -3 "$RUN/agent-recovery.log"
fi

sleep 10
docker logs "$CONTAINER" > "$RUN/wstest.log" 2>&1
docker stop "$CONTAINER" >/dev/null 2>&1
docker rm -f "$CONTAINER" >/dev/null 2>&1

echo "=== COLLECT REPORTS (kept even when the walk aborted) ==="
cp /tmp/java-fs-preflight.txt "$RUN/host-header-preflight.txt" 2>/dev/null
if [ -f "$REPORTS/index.json" ]; then
  cp "$REPORTS/index.json" "$RUN/index.json"
  for f in "$REPORTS"/*case*.json; do cp "$f" "$RUN/cases/"; done
  echo "case files: $(ls "$RUN/cases"/*.json 2>/dev/null | wc -l)"
else
  echo "::warning:: no index.json produced; recording the leg as incomplete"
  ls -la "$REPORTS/" || true
fi
echo "LEG_JAVA_FUZZINGSERVER_DONE agent_exit=$AGENT_EXIT"
