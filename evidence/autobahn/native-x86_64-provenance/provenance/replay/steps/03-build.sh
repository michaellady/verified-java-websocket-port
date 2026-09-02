#!/bin/bash
# Build every subject and harness binary this run needs, and record the
# digests of each one as it is produced.
set -euo pipefail
export PATH=/usr/local/go/bin:/opt/cargo/bin:$PATH
export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build

ATTEMPT="us019-prov-20260828T183623Z"
IMG="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
RUNTIME_SHA="eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f"
SUPPORT_SHA="e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9"
JB=/opt/vjwp/build/java
cd /opt/vjwp

echo "=== NATIVE ARCHITECTURE, READ OFF THIS MACHINE ==="
echo "uname -m: $(uname -m)"
echo "uname -r -v: $(uname -r -v)"
grep -m1 'model name' /proc/cpuinfo
grep -c '^processor' /proc/cpuinfo | sed 's/^/processors: /'
echo "docker arch: $(docker version --format '{{.Server.Arch}}')"
echo "--- binfmt_misc registrations (emulation would show here) ---"
ls /proc/sys/fs/binfmt_misc/ 2>/dev/null || echo "(binfmt_misc absent: no emulation registered)"

echo "=== PINNED IN-IMAGE TOOL DIGESTS ==="
docker run --rm --entrypoint sha256sum "$IMG" /opt/pypy/bin/wstest /opt/pypy/bin/pypy

echo "=== TOOLCHAINS ==="
gcc --version | head -1
java -version 2>&1 | head -2
javac -version 2>&1 | head -1

echo "=== GO BUILD autobahnsuitectl ==="
go mod download
mkdir -p /opt/vjwp/bin
go build -o /opt/vjwp/bin/autobahnsuitectl ./cmd/autobahnsuitectl
sha256sum /opt/vjwp/bin/autobahnsuitectl
/opt/vjwp/bin/autobahnsuitectl verify-manifest -root /opt/vjwp -manifest autobahn/case-manifest.json
echo "VERIFY_MANIFEST_EXIT=$?"

echo "=== RUST BUILD (ws-testee + autobahn-controls) ==="
cd /opt/vjwp/rust
cargo build --release -p ws-testee -p autobahn-controls 2>&1 | tail -20
sha256sum /opt/vjwp/rust/target/release/ws-testee
file /opt/vjwp/rust/target/release/ws-testee

echo "=== JAVA BASELINE: acquire the pinned Java-WebSocket 1.6.0 runtime ==="
mkdir -p "$JB/classes"
curl -fsSL -o "$JB/Java-WebSocket-1.6.0.jar" \
  https://repo1.maven.org/maven2/org/java-websocket/Java-WebSocket/1.6.0/Java-WebSocket-1.6.0.jar
echo "$RUNTIME_SHA  $JB/Java-WebSocket-1.6.0.jar" | sha256sum -c -
cp /opt/vjwp/.quarantine/slf4j-api-2.0.13.jar "$JB/slf4j-api-2.0.13.jar"
echo "$SUPPORT_SHA  $JB/slf4j-api-2.0.13.jar" | sha256sum -c -

echo "=== JAVA BASELINE: build the digest-bound Autobahn endpoint adapter ==="
cd /opt/vjwp
sha256sum autobahn-endpoint/src/main/java/AutobahnEndpoint.java
javac --release 17 -encoding UTF-8 -Xlint:all -Werror \
  -cp "$JB/Java-WebSocket-1.6.0.jar:$JB/slf4j-api-2.0.13.jar" \
  -d "$JB/classes" autobahn-endpoint/src/main/java/AutobahnEndpoint.java
jar --create --file "$JB/autobahn-endpoint.jar" --date=2026-01-01T00:00:00Z \
  --main-class AutobahnEndpoint -C "$JB/classes" .
ADAPTER_SHA=$(sha256sum "$JB/autobahn-endpoint.jar" | awk '{print $1}')
echo "ADAPTER_SHA=$ADAPTER_SHA"
echo "sha256:$ADAPTER_SHA" > "$JB/adapter-digest"

echo "=== JAVA BASELINE: endpoint self-test through its own binding gates ==="
java -cp "$JB/autobahn-endpoint.jar:$JB/Java-WebSocket-1.6.0.jar:$JB/slf4j-api-2.0.13.jar" \
  AutobahnEndpoint selftest \
  --adapter "$JB/autobahn-endpoint.jar" --adapter-digest "sha256:$ADAPTER_SHA" \
  --runtime "$JB/Java-WebSocket-1.6.0.jar" --support "$JB/slf4j-api-2.0.13.jar"
echo "JAVA_SELFTEST_EXIT=$?"

echo "=== DERIVED CONFIGS (agent and port are the only deltas from the pinned bytes) ==="
EV=/opt/vjwp/evidence/autobahn/native-x86_64-provenance
mkdir -p "$EV/config"
echo "$ATTEMPT" > "$EV/run-id"
cp /opt/vjwp/autobahn/fuzzingclient.json "$EV/config/fuzzingclient-rust.json"
sed -e 's#verified-rust-ws-testee-us019#verified-java-websocket-port-1.6.0#' \
    -e 's#ws://127.0.0.1:9010#ws://127.0.0.1:9011#' \
    /opt/vjwp/autobahn/fuzzingclient.json > "$EV/config/fuzzingclient-java.json"
cp /opt/vjwp/evidence/autobahn/dev-aarch64-nonauthoritative/fuzzingserver-run1/config-dev-derived.json \
   "$EV/config/fuzzingserver-derived.json"
echo "--- pinned source and both derivations ---"
sha256sum /opt/vjwp/autobahn/fuzzingclient.json \
  "$EV/config/fuzzingclient-rust.json" "$EV/config/fuzzingclient-java.json" \
  "$EV/config/fuzzingserver-derived.json"
echo "--- java fuzzingclient config, diffed against the pinned bytes ---"
diff /opt/vjwp/autobahn/fuzzingclient.json "$EV/config/fuzzingclient-java.json" || true
cat "$EV/config/fuzzingserver-derived.json"

echo "BUILD_OK"
