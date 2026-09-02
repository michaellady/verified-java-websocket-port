#!/bin/bash
# Leg R-B: Rust subject in the CLIENT-AGENT role, wstest serves as
# fuzzingserver. Bridge networking with a published port is the topology the
# derived ws://0.0.0.0:9001 spec was written for; --network host makes this
# mode reset the handshake.
set -uo pipefail
export PATH=/usr/local/go/bin:/opt/cargo/bin:$PATH
export HOME=/root GOPATH=/root/go
ATTEMPT="us019-prov-20260828T183623Z"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
EV=/opt/vjwp/evidence/autobahn/native-x86_64-provenance
P="$EV/provenance/rust-fuzzingserver"
RUN="$EV/rust/fuzzingserver-run1"
REPORTS="/opt/vjwp/capture/$ATTEMPT/reports-rust-fs"
CONTAINER="${ATTEMPT}-fs-rust"

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
docker logs "$CONTAINER" 2>&1 | grep -E "Fuzzing Server \(Port|Ok, will run" || true
if [ "$READY" -ne 1 ]; then
  echo "::error:: server never ready"; docker logs "$CONTAINER" 2>&1 | tail -20
  docker rm -f "$CONTAINER" >/dev/null 2>&1; exit 1
fi
sleep 2

echo "=== CAPTURE HARNESS CONTAINER PROVENANCE (while running) ==="
provcap container -name "$CONTAINER" -role harness-wstest-fuzzingserver \
  -label "$ATTEMPT/rust-fuzzingserver" -out "$P/harness-container.json"
echo "PROVCAP_HARNESS_EXIT=$?"

echo "=== HANDSHAKE PREFLIGHT ==="
python3 - <<'PY'
import socket, base64, os
key = base64.b64encode(os.urandom(16)).decode()
req = ("GET /getCaseCount HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\n"
       "Connection: Upgrade\r\n" + f"Sec-WebSocket-Key: {key}\r\n"
       + "Sec-WebSocket-Version: 13\r\n\r\n")
try:
    s = socket.create_connection(("127.0.0.1", 9001), timeout=10)
    s.sendall(req.encode()); s.settimeout(10)
    data = s.recv(2048)
    print("PREFLIGHT BYTES:", len(data)); print(repr(data[:200]))
except Exception as e:
    print("PREFLIGHT ERROR:", type(e).__name__, e)
PY

echo "=== RUN SUBJECT (Rust, client-agent role) ==="
/opt/vjwp/rust/target/release/ws-testee autobahn-client 127.0.0.1:9001 127.0.0.1:9001 \
  verified-rust-ws-testee-us019 > "$RUN/agent.log" 2>&1 &
AGENT_PID=$!
sleep 3
echo "AGENT_PID=$AGENT_PID"

echo "=== CAPTURE SUBJECT PROCESS PROVENANCE (while alive) ==="
provcap proc -pid "$AGENT_PID" -role subject-under-test-rust-client-agent \
  -label "$ATTEMPT/rust-fuzzingserver" -out "$P/subject-process.json"
echo "PROVCAP_SUBJECT_EXIT=$?"

wait $AGENT_PID
AGENT_EXIT=$?
echo "AGENT_EXIT=$AGENT_EXIT"
head -3 "$RUN/agent.log"; tail -2 "$RUN/agent.log"

sleep 10
docker logs "$CONTAINER" > "$RUN/wstest.log" 2>&1
docker stop "$CONTAINER" >/dev/null 2>&1
docker rm -f "$CONTAINER" >/dev/null 2>&1

echo "=== COLLECT REPORTS ==="
if [ ! -f "$REPORTS/index.json" ]; then
  echo "::error:: no index.json produced"; ls -la "$REPORTS/"; exit 1
fi
cp "$REPORTS/index.json" "$RUN/index.json"
for f in "$REPORTS"/*case*.json; do cp "$f" "$RUN/cases/"; done
echo "case files: $(ls "$RUN/cases"/*.json 2>/dev/null | wc -l)"
echo "LEG_RUST_FUZZINGSERVER_DONE agent_exit=$AGENT_EXIT"
