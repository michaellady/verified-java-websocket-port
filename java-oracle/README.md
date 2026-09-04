# Java-WebSocket semantic oracle

This is a dependency-free Java 17 JSONL adapter over the accepted
`org.java-websocket:Java-WebSocket:1.6.0` runtime. It does not modify or compile
upstream production source and it is not part of the upstream Maven test
inventory. The adapter compiles with `javac`, runs out of process, and loads its
runtime classpath externally.

At startup, the adapter locates the JAR that supplied `Draft_6455` and verifies
its bytes against the promoted digest:

`sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f`

A missing runtime, a classes directory in place of the JAR, or any other JAR
fails before the JSONL loop starts. The Java-WebSocket runtime also requires its
SLF4J API at runtime; supply that transitive runtime support through
`RUNTIME_SUPPORT_CP`. It is not an adapter dependency and is not bundled.

## Build and test

```text
make -C java-oracle test \
  JAVA_WEBSOCKET_JAR=/materialized/Java-WebSocket-1.6.0.jar \
  RUNTIME_SUPPORT_CP=/isolated-cache/slf4j-api.jar
```

The build uses `--release 17`, `-Xlint:all`, and `-Werror`. The pure Java test
harness covers deterministic replay, arbitrary input partitioning, local
actions, close transitions, Java runtime rejection, strict JSON, strict base64,
all resource limits, JSONL framing, canonical output, and stdout isolation.

The checked-in Maven project provides the same dependency-free build and fixed
test-harness execution required by the story:

```text
/materialized/apache-maven-3.9.11/bin/mvn \
  --file java-oracle/pom.xml --batch-mode --no-transfer-progress test \
  -Djava.websocket.jar=/materialized/Java-WebSocket-1.6.0.jar \
  -Druntime.support.classpath=/isolated-cache/slf4j-api.jar
```

`java.websocket.jar` is a system-scoped path by design: Maven never substitutes
a repository artifact for the promoted bytes, and the adapter re-hashes those
bytes at startup. The POM declares no test framework or repository dependency.
Every executed fixed-version plugin goal must already exist in the audited
Maven plugin closure; authoritative replay uses `--offline` and an isolated
local repository after that closure is promoted. Default resource and Surefire
executions are unbound, so the pure Java harness is the only test executor.

Run it with the same variables using `make -C java-oracle run`. Standard input
and standard output are UTF-8 JSONL. Standard output contains protocol records
only. Expected request failures are protocol responses; only bounded fatal
adapter diagnostics go to standard error.

## Protocol 1.0.0

Every input line is exactly one object with these fields. Unknown and duplicate
fields are rejected at every object boundary.

```json
{
  "protocol": "java-websocket-oracle",
  "version": "1.0.0",
  "request_digest": "sha256:<canonical-request-digest>",
  "request_id": "scenario-001",
  "role": "client",
  "initial_state": "open",
  "steps": [
    {"kind": "bytes", "data_base64": "gQJoaQ=="},
    {"kind": "action", "action": "send_ping", "data_base64": ""},
    {"kind": "action", "action": "send_close", "code": 1000, "reason": "done"},
    {"kind": "action", "action": "eof"}
  ],
  "limits": {
    "max_input_bytes": 1048576,
    "max_buffered_bytes": 1048576,
    "max_actions": 1024,
    "max_frames": 4096,
    "max_output_bytes": 4194304
  }
}
```

`role` is `client` or `server`. `initial_state` is `open`, `closing`, or
`closed`. Steps are ordered, so byte chunks and local actions may be interleaved.
Byte data is canonical RFC 4648 base64.

`request_digest` is SHA-256 over the UTF-8 canonical JSON object after removing
the `request_digest` member. Canonical objects use lexical key order with no
insignificant whitespace. The adapter independently recomputes and verifies the
digest before loading any scenario bytes into Java-WebSocket, then echoes the
binding on every request-scoped response.

Supported actions are:

- `send_text` with `text`
- `send_binary`, `send_ping`, and `send_pong` with `data_base64`
- `send_fragment` with `opcode` (`text` or `binary`), `data_base64`, and `fin`
- `send_close` with integer `code` and string `reason`
- `eof` with no additional fields

The caller chooses limits within hard adapter ceilings. A request cannot relax
the 1 MiB line/input/buffer ceilings, 1,024-action ceiling, 4,096-frame ceiling,
or 4 MiB output ceiling. Java-WebSocket receives `max_buffered_bytes` as its
maximum frame/message size. A request below its declared limit fails closed.

## Handshake protocol 1.0.0

Lines whose `protocol` is `java-websocket-handshake-oracle` route to the
handshake adapter. One line carries one US-005 handshake corpus case:

```json
{
  "protocol": "java-websocket-handshake-oracle",
  "version": "1.0.0",
  "request_digest": "sha256:<canonical-request-digest>",
  "case_id": "us005.hs.0000",
  "direction": "client_request",
  "raw_base64": "R0VUIC9jaGF0...",
  "config": {"max_handshake_bytes": 4096, "max_header_count": 32, "max_header_line_bytes": 512},
  "context": {"client_key": "dGhlIHNhbXBsZSBub25jZQ=="}
}
```

`direction` is `client_request` (raw bytes go through the server-side
`translateHandshake` / `acceptHandshakeAsServer` /
`postProcessHandshakeResponseAsServer` path) or `server_response` (raw bytes
go through the client-side `translateHandshake` / `acceptHandshakeAsClient`
path against `context.client_key`). The digest scheme is identical to the
behavior protocol; the distinct protocol id keeps behavior request digests
untouched. `config` is digest-bound but deliberately not enforced:
Java-WebSocket 1.6.0 itself enforces no handshake limits.

The response reports the runtime observable without interpretation:
`java_observable` is `accept` (with `sec_websocket_accept` read back out of
the rendered 101 bytes for `client_request`), `reject` (with `reject_channel`
`invalid_handshake` or `not_matched` and the runtime `close_code`), or
`incomplete` (`IncompleteHandshakeException`; a real server buffers and writes
nothing). RFC 6455 remains normative: the adapter reports Java behavior, and
the source-derived RFC-vs-Java verdict mapping lives in
`internal/corpora/handshake_live.go` and
`evidence/us005-handshake-live-mapping.json`. `corporactl oracle-requests
--tier handshake --wire` emits these request lines and `corporactl evaluate
--tier handshake --transcript FILE --live` scores the response transcript.

## Output

Success records contain normalized inbound and outbound semantic frames,
listener events, state transitions, close details, and exact input, consumed,
wire-buffered, message-buffered, action, and frame counts. Frame observations
include opcode, FIN/RSV/mask flags, semantic payload base64, payload size, and
wire size. Client output mask keys are intentionally absent: Java-WebSocket
randomizes them, while the semantic observation remains deterministic.

Object keys are emitted in lexical order, array order is observational order,
and the same request produces byte-identical output. Errors have stable typed
codes and bounded details; Java protocol errors include their close code. Partial
execution errors retain counts and final state. RFC 6455 remains normative: this
adapter reports Java behavior and does not claim that behavior is correct.

The adapter deliberately owns no sockets, clocks, caches, credentials, files,
or network policy. The qualification orchestrator supplies the exact runtime
classpath and enforces sandbox, source, cache, resource, and egress controls.
`internal/lab.EncodeJavaOracleRequest` is the sole legacy-to-wire translator,
and `internal/lab.RunJavaOracle` independently pins every classpath member,
enforces the JSONL boundary, and retains an exact response digest. The
`oraclee2e` Go test builds this adapter with the promoted JDK, executes the
accepted US-001 runtime twice, and proves both deterministic replay and typed
denial of planted response drift.
