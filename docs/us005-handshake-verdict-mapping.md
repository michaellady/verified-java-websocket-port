# US-005 handshake verdict mapping: Go reference model vs Java runtime

This document records how each verdict the Go reference model
(`internal/corpora/handshake.go`, `DeriveHandshake`) can emit maps onto the
behavior the real `org.java-websocket:Java-WebSocket:1.6.0` runtime observably
produces, and exactly where the two disagree. Nothing here was inferred from
documentation: every claim cites the quarantined source at revision
`da3cf2a777aed862f2f5b5cf060cae7969958667` (the digest-pinned archive in
`evidence/intake/source-pins.json`).

Jar-execution status, stated exactly: the 49-case committed census is
parity-model-derived from those cited source lines. The `java-oracle`
handshake harness has executed five synthetic representative divergence
families against the real digest-verified jar (missing Host, missing Upgrade,
non-base64 key, duplicated key, bare LF), plus synthetic reject, incomplete,
and client-direction probes. Zero committed-corpus cases have been executed
against the jar so far; the committed corpus is executed live in a later step
and scored fail-closed by `corporactl evaluate --tier handshake --live`.

The machine-checkable form of this mapping is
`evidence/us005-handshake-live-mapping.json`. It is rendered from
`corpora.HandshakeVerdictMapping()` and a Go test asserts the committed file
is byte-identical to the in-code table, so this document's table and the
adapter can never drift apart. Per-case resolution of the conditional rows is
`corpora.ExpectedJavaHandshakeObservable`, a line-referenced transcription of
the Java handshake path that the live evaluator
(`corporactl evaluate --tier handshake --live`) uses as its expectation.

## How the Java handshake path actually works

Read from the quarantined source:

- `Draft.readLine` (`Draft.java:70-88`) terminates a line only on the exact
  CRLF pair. A bare LF or bare CR stays inside the line.
- `Draft.translateHandshakeHttp` (`Draft.java:95-132`) splits the first line
  with `split(" ", 3)`, splits headers with `split(":", 2)`, strips only
  leading spaces from values, and joins duplicate header values with `"; "`.
  A missing first line or missing terminating empty line throws
  `IncompleteHandshakeException`; malformed lines throw
  `InvalidHandshakeException`.
- `Draft_6455.acceptHandshakeAsServer` (`Draft_6455.java:262-286`) checks
  exactly one thing: `Sec-WebSocket-Version` parses (after `String.trim`, via
  `Integer.parseInt`) to 13. The default draft's `DefaultExtension` and empty
  `Protocol("")` accept anything (`DefaultExtension.java:52-58`,
  `Protocol.java:58-61`). Host, Upgrade, Connection, and the key are never
  examined on the server side.
- `Draft_6455.postProcessHandshakeResponseAsServer`
  (`Draft_6455.java:432-441`) throws `InvalidHandshakeException` only for a
  missing or empty `Sec-WebSocket-Key`; otherwise it answers with
  `generateFinalKey(seckey)` (`Draft_6455.java:832-841`), the RFC 6455 SHA-1
  derivation over `String.trim(key)` with no base64 or length validation.
- `Draft_6455.acceptHandshakeAsClient` (`Draft_6455.java:306-343`) is the
  strict side: `basicAccept` (`Draft.java:188-191`) requires
  `Upgrade: websocket` (equalsIgnoreCase) and a `Connection` value containing
  `upgrade`, both key and accept must be present, and the accept value must
  literally equal `generateFinalKey(challenge)`.
- `WebSocketImpl.decodeHandshake` (`WebSocketImpl.java:248-389`) collapses
  every server-side rejection — parse failure, `NOT_MATCHED`, response-build
  failure — into one wire observable: an HTTP error response plus a
  `CloseFrame.PROTOCOL_ERROR` (1002) close
  (`WebSocketImpl.java:306-314, 426-429`). `IncompleteHandshakeException`
  buffers the bytes and writes nothing (`WebSocketImpl.java:370-387`).

## Observable granularity

The Java runtime exposes three observable classes, plus one draft-API-level
refinement the adapter can still see and report:

| observable | meaning | wire evidence |
|---|---|---|
| `accept` | handshake matched; for `client_request` the rendered 101 response carries `Sec-WebSocket-Accept` | the response bytes |
| `reject` / `invalid_handshake` | `InvalidHandshakeException` during parsing or response building | HTTP error + close 1002 |
| `reject` / `not_matched` | `HandshakeState.NOT_MATCHED` | HTTP error + close 1002 (server) or close 1002 (client) |
| `incomplete` | `IncompleteHandshakeException` | nothing written, bytes buffered |

On the real wire the two reject channels are indistinguishable (both are the
identical 404-plus-1002 sequence on a server); the channel is reported because
the adapter drives the draft API directly, and the evaluator pins it so a
mapping error fails loudly instead of being absorbed.

The 21+ distinct `HS_*` reject codes of the Go model therefore CANNOT be
recovered from Java observations. The adapter never guesses a reject code;
the evaluator instead projects each case's RFC expectation through this
mapping and compares at the granularity Java actually exposes.

## Divergences (RFC model rejects, Java observably accepts)

These are real behavioral disagreements, not vocabulary mismatches. Five
representative families are proven against the real jar by
`OracleMainTest.testHandshakeDivergentAccepts` (missing Host, missing Upgrade,
non-base64 key, duplicated key, bare LF); the remaining rows are
source-derived from the cited lines and await the live committed-corpus run
for jar confirmation. 16 of the 49 committed cases resolve through them:

| Go verdict | direction | Java observable | why |
|---|---|---|---|
| `HS_MISSING_HOST` | client_request | accept | Host is never read |
| `HS_MISSING_UPGRADE` | client_request | accept | server side never calls `basicAccept` |
| `HS_UPGRADE_VALUE` | client_request | accept | same |
| `HS_MISSING_CONNECTION` | client_request | accept | same |
| `HS_CONNECTION_VALUE` | client_request | accept | same |
| `HS_KEY_NOT_BASE64` | client_request | accept | `generateFinalKey` hashes any non-empty string; the accept value hashes the malformed key |
| `HS_KEY_LENGTH` | client_request | accept | decoded length never checked |
| `HS_DUPLICATE_HEADER` (key) | client_request | accept | duplicates join with `"; "`; the accept value hashes the joined string |
| `HS_HEADER_NAME_NOT_TOKEN` | client_request | accept | header names are never token-validated |
| `HS_BARE_LF` | client_request | accept | a bare-LF line folds into the following CRLF line; the surviving fields still pass the version-only check |
| `HS_LIMIT_TOTAL_BYTES` | client_request | accept | Java enforces no handshake limits |
| `HS_LIMIT_HEADER_COUNT` | client_request | accept | same |
| `HS_LIMIT_HEADER_LINE_BYTES` | client_request | accept | same |

`HS_DUPLICATE_HEADER` splits within one family: a duplicated
`Sec-WebSocket-Version` joins to `"13; 13"`, fails `Integer.parseInt`, and
rejects `not_matched` (agreeing with the RFC verdict class by accident), while
a duplicated `Sec-WebSocket-Key` joins and accepts. The conditional rows in
the mapping table name the deciding source behavior; the parity function
resolves each committed case exactly, and the coverage test asserts the
resolution for all 49 cases.

## Agreements with coarser granularity

Both sides reject, but Java cannot say which rule fired:

- `HS_MALFORMED_REQUEST_LINE`, `HS_METHOD_NOT_GET`, `HS_HTTP_VERSION`,
  `HS_OBS_FOLD`, `HS_MALFORMED_HEADER`, `HS_MISSING_KEY` → one
  `invalid_handshake` observable.
- `HS_MISSING_VERSION`, `HS_VERSION_UNSUPPORTED` → one `not_matched`
  observable.
- server_response: `HS_MALFORMED_STATUS_LINE`, `HS_HTTP_VERSION`,
  `HS_STATUS_NOT_101` → `invalid_handshake`; `HS_MISSING_UPGRADE`,
  `HS_UPGRADE_VALUE`, `HS_MISSING_CONNECTION`, `HS_CONNECTION_VALUE`,
  `HS_MISSING_ACCEPT`, `HS_ACCEPT_MISMATCH` → `not_matched`.

Granularity notes recorded in the table for inputs outside the committed
corpus: Java compares the method and HTTP version `equalsIgnoreCase` (a
lowercase `get` would be accepted), accepts any `Integer.parseInt` spelling of
13 (`+13`, `0013`, padded whitespace), requires exactly three status-line
tokens and the literal `101` on the client side, and the mapping is calibrated
for ASCII handshake bytes only (the corpus generator emits pure ASCII;
`ExpectedJavaHandshakeObservable` fails closed on anything else).

## What the adapter emits and how it is scored

`corporactl oracle-requests --tier handshake --wire` projects each case onto
the `java-websocket-handshake-oracle` protocol (digest-bound; documented in
`java-oracle/README.md`). The Java adapter (`HandshakeEngine.java`) feeds the
raw bytes through the real library path and emits one observable line per
case. `corporactl evaluate --tier handshake --transcript FILE --live` scores
the transcript fail-closed against `ExpectedJavaHandshakeObservable` —
observable class, reject channel, close code, accept value, digest binding,
presence parity — and lists every case that passed through a documented
divergence in the report's `divergences` field, so a reconciled live run can
never silently absorb an RFC-vs-Java disagreement.

This mapping calibrates the measurement instrument. It does not weaken the
port's obligations: RFC 6455 and the Go reference model remain normative for
the Rust port, and the divergences above are Java behaviors the port is not
required to reproduce.
